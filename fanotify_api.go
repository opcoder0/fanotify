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
	// ErrWatchPath indicates path needs to be specified for watching
	ErrWatchPath = errors.New("missing watch path")
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
	entireMount        bool
	watches            map[string]bool
	stopper            struct {
		r *os.File
		w *os.File
	}
	// Events a buffered channel holding fanotify notifications for the watched file/directory.
	Events chan Event
}

// NewListener returns a fanotify listener from which filesystem events
// can be read. Each listener supports listening to events
// under a single mountpoint.
//
// For cases where multiple mountpoints need to be monitored
// multiple listener instances need to be used.
//
// mountpoint can be any file/directory under the mount point being watched.
// Passing "true" to the entireMount flag monitors the entire mount point for marked
// events. Passing "false" allows specifying multiple paths (files/directories)
// under this mount point for monitoring filesystem events.
//
// The function returns a new instance of the listener. The fanotify flags are set
// based on the running kernel version. ErrCapSysAdmin is returned if the process does not
// have CAP_SYS_ADM capability.
//
//  - For Linux kernel version 5.0 and earlier no additional information about the underlying filesystem object is available.
//  - For Linux kernel versions 5.1 till 5.8 (inclusive) additional information about the underlying filesystem object is correlated to an event.
//  - For Linux kernel version 5.9 or later the modified file name is made available in the event.
func NewListener(mountPoint string, entireMount bool) (*Listener, error) {
	capSysAdmin, err := checkCapSysAdmin()
	if err != nil {
		return nil, err
	}
	if !capSysAdmin {
		return nil, ErrCapSysAdmin
	}
	return newListener(mountPoint, entireMount)
}

// Start starts the listener and polls the fanotify event notification group for marked events.
// The events are pushed into the Listener's `Events` buffered channel.
func (l *Listener) Start() {
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

// MarkMount adds, modifies or removes the fanotify mark (passed in as action) for the entire
// mountpoint. Passing true to remove, removes the mark from the mountpoint.
// This method returns an [ErrWatchPath] if the listener was not initialized to monitor
// the entire mountpoint. To mark specific files or directories use [AddWatch] method.
// The entire mount cannot be monitored for the following events:
// [FileCreated], [FileAttribChanged], [FileMovedFrom],
// [FileMovedTo], [WatchedFileDeleted]
// Passing any of these flags in action will return [ErrInvalidFlagCombination] error
func (l *Listener) MarkMount(action Action, remove bool) error {
	if l.entireMount == false {
		return ErrWatchPath
	}
	if action.Has(FileCreated) || action.Has(FileAttribChanged) || action.Has(FileMovedFrom) || action.Has(FileMovedTo) || action.Has(WatchedFileDeleted) {
		return ErrInvalidFlagCombination
	}
	if remove {
		return l.fanotifyMark(l.mountpoint.Name(), unix.FAN_MARK_REMOVE|unix.FAN_MARK_MOUNT, uint64(action), false)
	}
	return l.fanotifyMark(l.mountpoint.Name(), unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT, uint64(action), false)
}

// AddWatch adds or modifies the fanotify mark for the specified path.
// The events are only raised for the specified directory and does raise events
// for subdirectories. Calling AddWatch to mark the entire mountpoint results in
// [os.ErrInvalid]. To mark the entire mountpoint use [MarkMount] method.
// Certain flag combinations are known to cause issues.
//  - [FileCreated] cannot be or-ed / combined with FileClosed. The fanotify system does not generate any event for this combination.
//  - [FileOpened] with any of the actions containing OrDirectory causes an event flood for the directory and then stopping raising any events at all.
//  - [FileOrDirectoryOpened] with any of the other actions causes an event flood for the directory and then stopping raising any events at all.
func (l *Listener) AddWatch(path string, action Action) error {
	if l.entireMount {
		return os.ErrInvalid
	}
	return l.fanotifyMark(path, unix.FAN_MARK_ADD, uint64(action|unix.FAN_EVENT_ON_CHILD), false)
}

// DeleteWatch removes or modifies the fanotify mark for the specified path.
// Calling DeleteWatch on the listener initialized to monitor the entire mountpoint
// results in [os.ErrInvalid]. To modify the mark for the entire mountpoint use [MarkMount] method.
func (l *Listener) DeleteWatch(parentDir string, action Action) error {
	if l.entireMount {
		return os.ErrInvalid
	}
	return l.fanotifyMark(parentDir, unix.FAN_MARK_REMOVE, uint64(action|unix.FAN_EVENT_ON_CHILD), false)
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
