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
	ErrInvalidFlagCombination = errors.New("invalid flag bitmask")
	// ErrNilListener indicates the listener is nil
	ErrNilListener = errors.New("nil listener")
	// ErrUnsupportedOnKernelVersion indicates the feature/flag is unavailable for the current kernel version
	ErrUnsupportedOnKernelVersion = errors.New("feature unsupported on current kernel version")
	// ErrWatchPath indicates path needs to be specified for watching
	ErrWatchPath = errors.New("missing watch path")
)

// EventType represents an event / operation on a particular file/directory
type EventType uint64

// Event represents a notification from the kernel for the file, directory
// or a filesystem marked for watching.
type Event struct {
	// Fd is the open file descriptor for the file/directory being watched
	Fd int
	// Path holds the name of the parent directory
	Path string
	// FileName holds the name of the file under the watched parent. The value is only available
	// on kernels 5.1 or greater (that support the receipt of events which contain additional information
	// about the underlying filesystem object correlated to an event).
	FileName string
	// EventTypes holds bit mask representing the operations
	EventTypes EventType
	// Pid Process ID of the process that caused the event
	Pid int
}

// Listener represents a fanotify notification group that holds a list of files,
// directories or a mountpoint for which events shall be created.
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
// mountPoint can be any file/directory under the mount point being watched.
// entireMount when "true" monitors the entire mount point for marked
// events which includes all directories, subdirectories, and the
// contained files of the mount point. Passing "false" allows specifying
// multiple paths (files/directories)
// under this mount point for monitoring filesystem events using AddWatch.
//
// The function returns a new instance of the listener. The fanotify flags are set
// based on the running kernel version. [ErrCapSysAdmin] is returned if the process does not
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

// MarkMount adds, modifies or removes the fanotify mark (eventTypes) for the entire
// mount point. Passing true to remove, removes the mark from the mount point.
// This method returns an [ErrWatchPath] if the listener was not initialized to monitor
// the entire mount point. To mark specific files or directories use [AddWatch] method.
// The entire mount cannot be monitored for any events for which new directory modification
// events are provided. Passing any of these directory modification flags in eventTypes
// will return [ErrInvalidFlagCombination] error. Valid eventTypes are
// [FileAccessed], [FileOrDirectoryAccessed], [FileModified], [FileOpenedForExec]
// [FileOpened], [FileOrDirectoryOpened].
func (l *Listener) MarkMount(eventTypes EventType, remove bool) error {
	if l.entireMount == false {
		return ErrWatchPath
	}
	if eventTypes.Has(FileAttribChanged) ||
		eventTypes.Has(FileOrDirectoryAttribChanged) ||
		eventTypes.Has(FileCreated) ||
		eventTypes.Has(FileOrDirectoryCreated) ||
		eventTypes.Has(FileDeleted) ||
		eventTypes.Has(FileOrDirectoryDeleted) ||
		eventTypes.Has(WatchedFileDeleted) ||
		eventTypes.Has(WatchedFileOrDirectoryDeleted) ||
		eventTypes.Has(FileMovedTo) ||
		eventTypes.Has(FileMovedFrom) ||
		eventTypes.Has(WatchedFileMoved) ||
		eventTypes.Has(WatchedFileDeleted) {
		return ErrInvalidFlagCombination
	}
	if remove {
		return l.fanotifyMark(l.mountpoint.Name(), unix.FAN_MARK_REMOVE|unix.FAN_MARK_MOUNT, uint64(eventTypes), false)
	}
	return l.fanotifyMark(l.mountpoint.Name(), unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT, uint64(eventTypes), false)
}

// AddWatch adds or modifies the fanotify mark for the specified path.
// The events are only raised for the specified directory and does raise events
// for subdirectories. Calling AddWatch to mark the entire mountpoint results in
// [os.ErrInvalid]. To mark the entire mount point use [MarkMount] method.
// Certain flag combinations are known to cause issues.
//  - [FileCreated] cannot be or-ed / combined with [FileClosed]. The fanotify system does not generate any event for this combination.
//  - [FileOpened] with any of the event types containing OrDirectory causes an event flood for the directory and then stopping raising any events at all.
//  - [FileOrDirectoryOpened] with any of the other event types causes an event flood for the directory and then stopping raising any events at all.
func (l *Listener) AddWatch(path string, eventTypes EventType) error {
	if l.entireMount {
		return os.ErrInvalid
	}
	return l.fanotifyMark(path, unix.FAN_MARK_ADD, uint64(eventTypes|unix.FAN_EVENT_ON_CHILD), false)
}

// DeleteWatch removes or modifies the fanotify mark for the specified path.
// Calling DeleteWatch on the listener initialized to monitor the entire mount point
// results in [os.ErrInvalid]. To modify the mark for the entire mount point use [MarkMount] method.
func (l *Listener) DeleteWatch(parentDir string, eventTypes EventType) error {
	if l.entireMount {
		return os.ErrInvalid
	}
	return l.fanotifyMark(parentDir, unix.FAN_MARK_REMOVE, uint64(eventTypes|unix.FAN_EVENT_ON_CHILD), false)
}

// ClearWatch stops watching for all event types
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

// Has returns true if event types (e) contains the passed in event type (et).
func (e EventType) Has(et EventType) bool {
	return e&et == et
}

// Or appends the specified event types to the set of event types to watch for
func (e EventType) Or(et EventType) EventType {
	return e | et
}

// String prints event types
func (e EventType) String() string {
	var eventTypes = map[EventType]string{
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
	var eventTypeList []string
	for k, v := range eventTypes {
		if e.Has(k) {
			eventTypeList = append(eventTypeList, v)
		}
	}
	return strings.Join(eventTypeList, ",")
}

func (e Event) String() string {
	return fmt.Sprintf("Fd:(%d), Pid:(%d), EventType:(%s), Path:(%s), Filename:(%s)", e.Fd, e.Pid, e.EventTypes, e.Path, e.FileName)
}
