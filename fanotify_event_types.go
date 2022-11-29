package fanotify

import "golang.org/x/sys/unix"

const (
	// FileOrDirAccessedEvent create an event when a file or directory is accessed
	FileOrDirAccessedEvent uint64 = unix.FAN_ACCESS
	// FileModifiedEvent create an event when a file is modified
	FileModifiedEvent uint64 = unix.FAN_MODIFY
	// FileClosedEvent create an event when a file is closed
	FileClosedEvent uint64 = unix.FAN_CLOSE_WRITE | unix.FAN_CLOSE_NOWRITE
	// FileOrDirOpenedEvent create an event when a file or directory is opened
	FileOrDirOpenedEvent uint64 = unix.FAN_OPEN
	// FileOpenedForExecEvent create an event when a file is opened with the intent to be executed.
	FileOpenedForExecEvent uint64 = unix.FAN_OPEN_EXEC
	// FileOrDirMetadataChangedEvent create an event when a file or directory attributes have changed.
	FileOrDirMetadataChangedEvent uint64 = unix.FAN_ATTRIB
	// DirectoryEvent create an event when directory is opened, read or closed.
	DirectoryEvent uint64 = unix.FAN_ONDIR
	// FileCreatedInMarkedParentEvent create event when a file is created under a marked parent directory.
	FileCreatedInMarkedParentEvent uint64 = unix.FAN_CREATE | unix.FAN_EVENT_ON_CHILD
	// DirectoryCreatedInMarkedParentEvent create event when a directory is created under a marked parent directory.
	DirectoryCreatedInMarkedParentEvent uint64 = unix.FAN_ONDIR | unix.FAN_CREATE | unix.FAN_EVENT_ON_CHILD
	// FileDeletedInMarkedParentEvent create event when a file is deleted under a marked parent directory.
	FileDeletedInMarkedParentEvent uint64 = unix.FAN_DELETE | unix.FAN_EVENT_ON_CHILD
	// DirectoryDeletedInMarkedParentEvent create event when a directory is deleted under a marked parent directory.
	DirectoryDeletedInMarkedParentEvent uint64 = unix.FAN_ONDIR | unix.FAN_DELETE | unix.FAN_EVENT_ON_CHILD
	// MarkedFileDeletedEvent create event when a marked file is deleted.
	MarkedFileDeletedEvent uint64 = unix.FAN_DELETE_SELF
	// MarkedDirectoryDeletedEvent create an event when a marked directory is deleted.
	MarkedDirectoryDeletedEvent uint64 = unix.FAN_ONDIR | unix.FAN_DELETE_SELF
	// FileMovedFromMarkedParentEvent create an event when file has been moved from a marked parent directory.
	FileMovedFromMarkedParentEvent uint64 = unix.FAN_MOVED_FROM | unix.FAN_EVENT_ON_CHILD
	// DirMovedFromMarkedParentEvent create an event when a directory has been moved from a marked parent directory.
	DirMovedFromMarkedParentEvent uint64 = unix.FAN_ONDIR | unix.FAN_MOVED_FROM | unix.FAN_EVENT_ON_CHILD
	// FileMovedToMarkedParentEvent create an event when file has been moved to a marked parent directory.
	FileMovedToMarkedParentEvent uint64 = unix.FAN_MOVED_TO | unix.FAN_EVENT_ON_CHILD
	// DirMovedToMarkedParentEvent create an event when a directory has been moved to a marked parent directory.
	DirMovedToMarkedParentEvent uint64 = unix.FAN_ONDIR | unix.FAN_MOVED_TO | unix.FAN_EVENT_ON_CHILD
	// MarkedFileOrDirectoryHasMovedEvent create an event when a marked file or directory has moved.
	MarkedFileOrDirectoryHasMovedEvent uint64 = unix.FAN_MOVE_SELF
	// QueueOverflowedEvent create an event when the kernel event queue has overflowed.
	QueueOverflowedEvent uint64 = unix.FAN_Q_OVERFLOW
	// FileOrDirectoryMovedEvent create an event when a file or directory has moved.
	FileOrDirectoryMovedEvent uint64 = FileMovedFromMarkedParentEvent | FileMovedToMarkedParentEvent | DirMovedFromMarkedParentEvent | DirMovedToMarkedParentEvent
)
