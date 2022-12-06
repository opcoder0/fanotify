//go:build linux
// +build linux

package fanotify

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

var (
	// ErrCapSysAdmin indicates caller is missing CAP_SYS_ADMIN permissions
	ErrCapSysAdmin = errors.New("require CAP_SYS_ADMIN capability")
	// ErrInvalidFlagCombination indicates the bit/combination of flags are invalid
	ErrInvalidFlagCombination = errors.New("invalid flag bits")
	// ErrNilListener indicates the listener is nil
	ErrNilListener = errors.New("nil listener")
	// ErrUnsupportedOnKernelVersion indicates the feature/flag is unavailable for the current kernel version
	ErrUnsupportedOnKernelVersion = errors.New("feature unsupported on current kernel version")
)

// Action represents an event / operation on a particular file/directory
type Action uint64

// Event represents a notification from the kernel for the file, directory
// or a filesystem marked for watching.
type Event struct {
	// Fd is the open file descriptor for the file/directory being watched
	Fd int
	// Path holds the name of the parent directory
	Path string
	// FileName holds the name of the file under the watched parent. The value is only available
	// when NewListener is created by passing `true` with `withName` argument. The feature is available
	// only with kernels 5.9 or higher.
	FileName string
	// Actions holds bit mask representing the operations
	Actions Action
	// Pid Process ID of the process that caused the event
	Pid int
}

// Listener represents a fanotify notification group that holds a list of files,
// directories and filesystems under a given mountpoint for which events shall be created.
type Listener struct {
	// fd returned by fanotify_init
	fd int
	// flags passed to fanotify_init
	flags uint
	// mount fd is the file descriptor of the mountpoint
	mountpoint         *os.File
	kernelMajorVersion int
	kernelMinorVersion int
	watches            map[string]bool
	stopper            struct {
		r *os.File
		w *os.File
	}
	// Events a buffered channel holding fanotify notifications for the watched file/directory.
	Events chan Event
}

// NewListener returns a fanotify listener from which events
// can be read. Each listener supports listening to events
// under a single mount point.
//
// For cases where multiple mountpoints need to be monitored
// multiple listener instances need to be used.
//
// `mountpointPath` can be any file/directory under the mount point being watched.
// `maxEvents` defines the length of the buffered channel which holds the notifications. The minimum length is 4096.
// `withName` setting this to true populates the file name under the watched parent.
//
// NOTE that this call requires CAP_SYS_ADMIN privilege
func NewListener(mountpointPath string, maxEvents uint, withName bool) (*Listener, error) {
	capSysAdmin, err := checkCapSysAdmin()
	if err != nil {
		return nil, err
	}
	if !capSysAdmin {
		return nil, ErrCapSysAdmin
	}
	if maxEvents < 4096 {
		maxEvents = 4096
	}
	var flags, eventFlags uint
	if withName {
		flags = unix.FAN_CLASS_NOTIF | unix.FAN_CLOEXEC | unix.FAN_REPORT_DIR_FID | unix.FAN_REPORT_NAME
	} else {
		flags = unix.FAN_CLASS_NOTIF | unix.FAN_CLOEXEC | unix.FAN_REPORT_FID
	}

	eventFlags = unix.O_RDONLY | unix.O_LARGEFILE | unix.O_CLOEXEC
	return newListener(mountpointPath, flags, eventFlags, maxEvents)
}

// Start starts the listener and polls the fanotify event notification group for marked events.
// The events are pushed into the Listener's `Events` buffered channel.
// The function panics if there nothing to watch.
func (l *Listener) Start() {
	//if len(l.watches) == 0 {
	//		panic("Nothing to watch. Add Directory/File to the listener to watch")
	//}
	var fds [2]unix.PollFd
	// Fanotify Fd
	fds[0].Fd = int32(l.fd)
	fds[0].Events = unix.POLLIN
	// Stopper/Cancellation Fd
	fds[1].Fd = int32(l.stopper.r.Fd())
	fds[1].Events = unix.POLLIN
	for {
		n, err := unix.Poll(fds[:], -1)
		if n == 0 {
			continue
		}
		if err != nil {
			if err == unix.EINTR {
				continue
			} else {
				// TODO handle error
				return
			}
		}
		if fds[1].Revents != 0 {
			if fds[1].Revents&unix.POLLIN == unix.POLLIN {
				// found data on the stopper
				return
			}
		}
		if fds[0].Revents != 0 {
			if fds[0].Revents&unix.POLLIN == unix.POLLIN {
				l.readEvents() // blocks when the channel bufferred is full
			}
		}
	}
}

// Stop stops the listener and closes the notification group and the events channel
func (l *Listener) Stop() {
	if l == nil {
		return
	}
	// stop the listener
	unix.Write(int(l.stopper.w.Fd()), []byte("stop"))
	l.mountpoint.Close()
	l.stopper.r.Close()
	l.stopper.w.Close()
	close(l.Events)
}

// AddWatch watches parent directory for specified actions
func (l *Listener) AddWatch(parentDir string, action Action) error {
	return l.fanotifyMark(parentDir, unix.FAN_MARK_ADD, uint64(action|unix.FAN_EVENT_ON_CHILD), false)
}

// DeleteWatch stops watching the parent directory for the specified action
func (l *Listener) DeleteWatch(parentDir string, action Action) error {
	return l.fanotifyMark(parentDir, unix.FAN_MARK_REMOVE, uint64(action|unix.FAN_EVENT_ON_CHILD), false)
}

// WatchMountPoint watches the entire mount point for specified actions
func (l *Listener) WatchMountPoint(action Action) error {
	return l.fanotifyMark(l.mountpoint.Name(), unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT, uint64(action), false)
}

// ClearWatch stops watching for all actions
func (l *Listener) ClearWatch() error {
	if l == nil {
		return ErrNilListener
	}
	if err := unix.FanotifyMark(l.fd, unix.FAN_MARK_FLUSH, 0, -1, ""); err != nil {
		return err
	}
	l.watches = make(map[string]bool)
	return nil
}

// Has returns true if actions contains the passed in action (a).
func (actions Action) Has(a Action) bool {
	return actions&a == a
}

// Or appends the specified action to the set of actions to watch for
func (actions Action) Or(a Action) Action {
	return actions | a
}

// String prints action
func (a Action) String() string {
	var actions = map[Action]string{
		unix.FAN_ACCESS:        "Access",
		unix.FAN_MODIFY:        "Modify",
		unix.FAN_CLOSE_WRITE:   "CloseWrite",
		unix.FAN_CLOSE_NOWRITE: "CloseNoWrite",
		unix.FAN_OPEN:          "Open",
		unix.FAN_OPEN_EXEC:     "OpenExec",
		unix.FAN_ATTRIB:        "AttribChange",
		unix.FAN_CREATE:        "Create",
		unix.FAN_DELETE:        "Delete",
		unix.FAN_DELETE_SELF:   "SelfDelete",
		unix.FAN_MOVED_FROM:    "MovedFrom",
		unix.FAN_MOVED_TO:      "MovedTo",
		unix.FAN_MOVE_SELF:     "SelfMove",
	}
	var actionList []string
	for k, v := range actions {
		if a.Has(k) {
			actionList = append(actionList, v)
		}
	}
	return strings.Join(actionList, ",")
}

func (e Event) String() string {
	return fmt.Sprintf("Fd:(%d), Pid:(%d), Action:(%s), Path:(%s), Filename:(%s)", e.Fd, e.Pid, e.Actions, e.Path, e.FileName)
}
