package fanotify

import "golang.org/x/sys/unix"

const (
	// FileOrDirAccessedEvent create an event when a file or directory is accessed
	FileOrDirAccessedEvent EventMask = unix.FAN_ACCESS
	// FileModifiedEvent create an event when a file is modified
	FileModifiedEvent EventMask = unix.FAN_MODIFY
	// FileClosedEvent create an event when a file is closed
	FileClosedEvent EventMask = unix.FAN_CLOSE_WRITE | unix.FAN_CLOSE_NOWRITE
	// FileOrDirOpenedEvent create an event when a file or directory is opened
	FileOrDirOpenedEvent EventMask = unix.FAN_OPEN
	// FileOpenedForExecEvent create an event when a file is opened with the intent to be executed.
	FileOpenedForExecEvent EventMask = unix.FAN_OPEN_EXEC
	// FileOrDirMetadataChangedEvent create an event when a file or directory attributes have changed.
	FileOrDirMetadataChangedEvent EventMask = unix.FAN_ATTRIB
	// DirectoryEvent create an event when directory is opened, read or closed.
	DirectoryEvent EventMask = unix.FAN_ONDIR
	// FileCreatedInMarkedParentEvent create event when a file is created under a marked parent directory.
	FileCreatedInMarkedParentEvent EventMask = unix.FAN_CREATE | unix.FAN_EVENT_ON_CHILD
	// DirectoryCreatedInMarkedParentEvent create event when a directory is created under a marked parent directory.
	DirectoryCreatedInMarkedParentEvent EventMask = unix.FAN_ONDIR | unix.FAN_CREATE | unix.FAN_EVENT_ON_CHILD
	// FileDeletedInMarkedParentEvent create event when a file is deleted under a marked parent directory.
	FileDeletedInMarkedParentEvent EventMask = unix.FAN_DELETE | unix.FAN_EVENT_ON_CHILD
	// DirectoryDeletedInMarkedParentEvent create event when a directory is deleted under a marked parent directory.
	DirectoryDeletedInMarkedParentEvent EventMask = unix.FAN_ONDIR | unix.FAN_DELETE | unix.FAN_EVENT_ON_CHILD
	// MarkedFileDeletedEvent create event when a marked file is deleted.
	MarkedFileDeletedEvent EventMask = unix.FAN_DELETE_SELF
	// MarkedDirectoryDeletedEvent create an event when a marked directory is deleted.
	MarkedDirectoryDeletedEvent EventMask = unix.FAN_ONDIR | unix.FAN_DELETE_SELF
	// FileMovedFromMarkedParentEvent create an event when file has been moved from a marked parent directory.
	FileMovedFromMarkedParentEvent EventMask = unix.FAN_MOVED_FROM | unix.FAN_EVENT_ON_CHILD
	// DirMovedFromMarkedParentEvent create an event when a directory has been moved from a marked parent directory.
	DirMovedFromMarkedParentEvent EventMask = unix.FAN_ONDIR | unix.FAN_MOVED_FROM | unix.FAN_EVENT_ON_CHILD
	// FileMovedToMarkedParentEvent create an event when file has been moved to a marked parent directory.
	FileMovedToMarkedParentEvent EventMask = unix.FAN_MOVED_TO | unix.FAN_EVENT_ON_CHILD
	// DirMovedToMarkedParentEvent create an event when a directory has been moved to a marked parent directory.
	DirMovedToMarkedParentEvent EventMask = unix.FAN_ONDIR | unix.FAN_MOVED_TO | unix.FAN_EVENT_ON_CHILD
	// MarkedFileOrDirectoryHasMovedEvent create an event when a marked file or directory has moved.
	MarkedFileOrDirectoryHasMovedEvent EventMask = unix.FAN_MOVE_SELF
	// QueueOverflowedEvent create an event when the kernel event queue has overflowed.
	QueueOverflowedEvent EventMask = unix.FAN_Q_OVERFLOW
	// FileOrDirectoryMovedEvent create an event when a file or directory has moved.
	FileOrDirectoryMovedEvent EventMask = FileMovedFromMarkedParentEvent | FileMovedToMarkedParentEvent | DirMovedFromMarkedParentEvent | DirMovedToMarkedParentEvent
)
