//go:build linux
// +build linux

package fanotify

import (
	"errors"
	"os"

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
	// Mask holds bit mask representing the operation
	Mask uint64
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
	if len(l.watches) == 0 {
		panic("Nothing to watch. Add Directory/File to the listener to watch")
	}
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

func (l *Listener) WatchFileOrDirAccessed(dir string) error {
	return l.fanotifyMark(dir, unix.FAN_MARK_ADD|unix.FAN_MARK_ONLYDIR, unix.FAN_ACCESS, false)
}

func (l *Listener) WatchFileModified(dir string) error {
	return l.fanotifyMark(dir, unix.FAN_MARK_ADD|unix.FAN_MARK_ONLYDIR, unix.FAN_MODIFY, false)
}

// // AddDir adds the specified directory to listener's watch
// // list. If `dir` is not a directory then an error is returned.
// // If `dir` is a symbolic link the link is followed.
// func (l *Listener) AddDir(dir string, events uint64) error {
// 	var flags uint
// 	flags = unix.FAN_MARK_ADD | unix.FAN_MARK_ONLYDIR
// 	return l.fanotifyMark(dir, flags, events, false)
// }
//
// // RemoveDir removes the specified directory from the listener's
// // watch list.
// func (l *Listener) RemoveDir(dir string, events uint64) error {
// 	var flags uint
// 	flags = unix.FAN_MARK_REMOVE | unix.FAN_MARK_ONLYDIR
// 	return l.fanotifyMark(dir, flags, events, true)
// }
//
// // AddLink adds the specified symbolic link to the listener's watch list. The link
// // is not followed. The link itself is marked for watching.
// func (l *Listener) AddLink(linkName string, events uint64) error {
// 	var flags uint
// 	flags = unix.FAN_MARK_ADD | unix.FAN_MARK_DONT_FOLLOW
// 	return l.fanotifyMark(linkName, flags, events, false)
// }
//
// // RemoveLink removes the specified symbolic link from the listener's watch list.
// func (l *Listener) RemoveLink(linkName string, events uint64) error {
// 	var flags uint
// 	flags = unix.FAN_MARK_REMOVE | unix.FAN_MARK_DONT_FOLLOW
// 	return l.fanotifyMark(linkName, flags, events, true)
// }
//
// // AddPath adds the specified path name (file or directory) to the listener's
// // watch list.
// func (l *Listener) AddPath(path string, events uint64) error {
// 	return l.fanotifyMark(path, unix.FAN_MARK_ADD, events, false)
// }
//
// // RemovePath removes the specified path name (file or directory) from the
// // listener's watch list.
// func (l *Listener) RemovePath(path string, events uint64) error {
// 	return l.fanotifyMark(path, unix.FAN_MARK_REMOVE, events, true)
// }
//
// // RemoveAll removes all the watch elements from the listener.
// func (l *Listener) RemoveAll() error {
// 	if l == nil {
// 		return ErrNilListener
// 	}
// 	if err := unix.FanotifyMark(l.fd, unix.FAN_MARK_FLUSH, 0, -1, ""); err != nil {
// 		return err
// 	}
// 	l.watches = make(map[string]bool)
// 	return nil
// }
