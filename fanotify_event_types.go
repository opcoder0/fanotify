package fanotify

import "golang.org/x/sys/unix"

var (
	// FileOrDirAccessedEvent create an event when a file or directory is accessed
	FileOrDirAccessedEvent = unix.FAN_ACCESS
	// FileModifiedEvent create an event when a file is modified
	FileModifiedEvent = unix.FAN_MODIFY
	// FileClosedEvent create an event when a file is closed
	FileClosedEvent = unix.FAN_CLOSE_WRITE | unix.FAN_CLOSE_NOWRITE
	// FileOrDirOpenedEvent create an event when a file or directory is opened
	FileOrDirOpenedEvent = unix.FAN_OPEN
	// FileOpenedForExecEvent create an event when a file is opened with the intent to be executed.
	FileOpenedForExecEvent = unix.FAN_OPEN_EXEC
	// FileOrDirMetadataChangedEvent create an event when a file or directory attributes have changed.
	FileOrDirMetadataChangedEvent = unix.FAN_ATTRIB
	// DirectoryEvent create an event when directory is opened, read or closed.
	DirectoryEvent = unix.FAN_ONDIR
	// FileCreatedInMarkedParentEvent create event when a file is created under a marked parent directory.
	FileCreatedInMarkedParentEvent = unix.FAN_CREATE | unix.FAN_EVENT_ON_CHILD
	// DirectoryCreatedInMarkedParentEvent create event when a directory is created under a marked parent directory.
	DirectoryCreatedInMarkedParentEvent = unix.FAN_ONDIR | unix.FAN_CREATE | unix.FAN_EVENT_ON_CHILD
	// FileDeletedInMarkedParentEvent create event when a file is deleted under a marked parent directory.
	FileDeletedInMarkedParentEvent = unix.FAN_DELETE | unix.FAN_EVENT_ON_CHILD
	// DirectoryDeletedInMarkedParentEvent create event when a directory is deleted under a marked parent directory.
	DirectoryDeletedInMarkedParentEvent = unix.FAN_ONDIR | unix.FAN_DELETE | unix.FAN_EVENT_ON_CHILD
	// MarkedFileDeletedEvent create event when a marked file is deleted.
	MarkedFileDeletedEvent = unix.FAN_DELETE_SELF
	// MarkedDirectoryDeletedEvent create an event when a marked directory is deleted.
	MarkedDirectoryDeletedEvent = unix.FAN_ONDIR | unix.FAN_DELETE_SELF
	// FileMovedFromMarkedParentEvent create an event when file has been moved from a marked parent directory.
	FileMovedFromMarkedParentEvent = unix.FAN_MOVED_FROM | unix.FAN_EVENT_ON_CHILD
	// DirMovedFromMarkedParentEvent create an event when a directory has been moved from a marked parent directory.
	DirMovedFromMarkedParentEvent = unix.FAN_ONDIR | unix.FAN_MOVED_FROM | unix.FAN_EVENT_ON_CHILD
	// FileMovedToMarkedParentEvent create an event when file has been moved to a marked parent directory.
	FileMovedToMarkedParentEvent = unix.FAN_MOVED_TO | unix.FAN_EVENT_ON_CHILD
	// DirMovedToMarkedParentEvent create an event when a directory has been moved to a marked parent directory.
	DirMovedToMarkedParentEvent = unix.FAN_ONDIR | unix.FAN_MOVED_TO | unix.FAN_EVENT_ON_CHILD
	// MarkedFileOrDirectoryHasMovedEvent create an event when a marked file or directory has moved.
	MarkedFileOrDirectoryHasMovedEvent = unix.FAN_MOVE_SELF
	// QueueOverflowedEvent create an event when the kernel event queue has overflowed.
	QueueOverflowedEvent = unix.FAN_Q_OVERFLOW
	// FileOrDirectoryMovedEvent create an event when a file or directory has moved.
	FileOrDirectoryMovedEvent = FileMovedFromMarkedParentEvent | FileMovedToMarkedParentEvent | DirMovedFromMarkedParentEvent | DirMovedToMarkedParentEvent
)
