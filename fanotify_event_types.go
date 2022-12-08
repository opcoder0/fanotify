package fanotify

import "golang.org/x/sys/unix"

const (
	// FileAccessed event when a file is accessed
	FileAccessed Action = unix.FAN_ACCESS

	// FileOrDirectoryAccessed event when a file or directory is accessed
	FileOrDirectoryAccessed Action = unix.FAN_ACCESS | unix.FAN_ONDIR

	// FileModified event when a file is modified
	FileModified Action = unix.FAN_MODIFY

	// FileClosedAfterWrite event when a file is closed
	FileClosedAfterWrite Action = unix.FAN_CLOSE_WRITE

	// FileClosedWithNoWrite event when a file is closed without writing
	FileClosedWithNoWrite Action = unix.FAN_CLOSE_NOWRITE

	// FileClosed event when a file is closed after write or no write
	FileClosed Action = unix.FAN_CLOSE_WRITE | unix.FAN_CLOSE_NOWRITE

	// FileOpened event when a file is opened
	// BUG Using FileOpened flag with any OrDirectory actions
	// causes an event flood and complete stoppage of events. The flag
	// can be used with other file only flags or by itself
	// without any errors/issues.
	FileOpened Action = unix.FAN_OPEN

	// FileOrDirectoryOpened event when a file or directory is opened
	// BUG Using FileOrDirectoryOpened causes an event flood and complete
	// stoppage of events. The flag by itself without any errors/issues.
	FileOrDirectoryOpened Action = unix.FAN_OPEN | unix.FAN_ONDIR

	// FileOpenedForExec event when a file is opened with the intent to be executed.
	// Requires Linux kernel 5.0 or later
	FileOpenedForExec Action = unix.FAN_OPEN_EXEC

	// FileAttribChanged event when a file attribute has changed
	// Requires Linux kernel 5.1 or later (requires FID)
	FileAttribChanged Action = unix.FAN_ATTRIB

	// FileOrDirectoryAttribChanged event when a file or directory attribute has changed
	// Requires Linux kernel 5.1 or later (requires FID)
	FileOrDirectoryAttribChanged Action = unix.FAN_ATTRIB | unix.FAN_ONDIR

	// FileCreated event when file a has been created
	// Requires Linux kernel 5.1 or later (requires FID)
	// BUG FileCreated does not work with FileClosed, FileClosedAfterWrite or FileClosedWithNoWrite
	FileCreated Action = unix.FAN_CREATE

	// FileOrDirectoryCreated event when a file or directory has been created
	// Requires Linux kernel 5.1 or later (requires FID)
	FileOrDirectoryCreated Action = unix.FAN_CREATE | unix.FAN_ONDIR

	// FileDeleted event when file a has been deleted
	// Requires Linux kernel 5.1 or later (requires FID)
	FileDeleted Action = unix.FAN_DELETE

	// FileOrDirectoryDeleted event when a file or directory has been deleted
	// Requires Linux kernel 5.1 or later (requires FID)
	FileOrDirectoryDeleted Action = unix.FAN_DELETE | unix.FAN_ONDIR

	// WatchedFileDeleted event when a watched file has been deleted
	// Requires Linux kernel 5.1 or later (requires FID)
	WatchedFileDeleted Action = unix.FAN_DELETE_SELF

	// WatchedFileOrDirectoryDeleted event when a watched file or directory has been deleted
	// Requires Linux kernel 5.1 or later (requires FID)
	WatchedFileOrDirectoryDeleted Action = unix.FAN_DELETE_SELF | unix.FAN_ONDIR

	// FileMovedFrom event when a file has been moved from the watched directory
	// Requires Linux kernel 5.1 or later (requires FID)
	FileMovedFrom Action = unix.FAN_MOVED_FROM

	// FileOrDirectoryMovedFrom event when a file or directory has been moved from the watched directory
	// Requires Linux kernel 5.1 or later (requires FID)
	FileOrDirectoryMovedFrom Action = unix.FAN_MOVED_FROM | unix.FAN_ONDIR

	// FileMovedTo event when a file has been moved to the watched directory
	// Requires Linux kernel 5.1 or later (requires FID)
	FileMovedTo Action = unix.FAN_MOVED_TO

	// FileOrDirectoryMovedTo event when a file or directory has been moved to the watched directory
	// Requires Linux kernel 5.1 or later (requires FID)
	FileOrDirectoryMovedTo Action = unix.FAN_MOVED_TO | unix.FAN_ONDIR

	// WatchedFileMoved event when a watched file has moved
	// Requires Linux kernel 5.1 or later (requires FID)
	WatchedFileMoved Action = unix.FAN_MOVE_SELF

	// WatchedFileOrDirectoryMoved event when a watched file or directory has moved
	// Requires Linux kernel 5.1 or later (requires FID)
	WatchedFileOrDirectoryMoved Action = unix.FAN_MOVE_SELF | unix.FAN_ONDIR
)
