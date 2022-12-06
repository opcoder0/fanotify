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
	FileOpened Action = unix.FAN_OPEN

	// FileOrDirectoryOpened event when a file or directory is opened
	FileOrDirectoryOpened Action = unix.FAN_OPEN | unix.FAN_ONDIR

	// FileOpenedForExec event when a file is opened with the intent to be executed.
	// Requires Linux kernel 5.0 or later
	FileOpenedForExec Action = unix.FAN_OPEN_EXEC

	// FileAttribChanged event when a file attribute has changed
	// Requires Linux kernel 5.1 or later (requires FID)
	FileAttribChanged Action = unix.FAN_ATTRIB

	// FileOrDirAttribChanged event when a file or directory attribute has changed
	// Requires Linux kernel 5.1 or later (requires FID)
	FileOrDirAttribChanged Action = unix.FAN_ATTRIB | unix.FAN_ONDIR

	// FileCreated event when file a has been created
	// Requires Linux kernel 5.1 or later (requires FID)
	FileCreated Action = unix.FAN_CREATE

	// FileOrDirCreated event when a file or directory has been created
	// Requires Linux kernel 5.1 or later (requires FID)
	FileOrDirCreated Action = unix.FAN_CREATE | unix.FAN_ONDIR

	// FileDeleted event when file a has been deleted
	// Requires Linux kernel 5.1 or later (requires FID)
	FileDeleted Action = unix.FAN_DELETE

	// FileOrDirDeleted event when a file or directory has been deleted
	// Requires Linux kernel 5.1 or later (requires FID)
	FileOrDirDeleted Action = unix.FAN_DELETE | unix.FAN_ONDIR

	// WatchedFileDeleted event when a watched file has been deleted
	// Requires Linux kernel 5.1 or later (requires FID)
	WatchedFileDeleted Action = unix.FAN_DELETE_SELF

	// WatchedFileOrDirDeleted event when a watched file or directory has been deleted
	// Requires Linux kernel 5.1 or later (requires FID)
	WatchedFileOrDirDeleted Action = unix.FAN_DELETE_SELF | unix.FAN_ONDIR

	// FileMovedFrom event when a file has been moved from the watched directory
	// Requires Linux kernel 5.1 or later (requires FID)
	FileMovedFrom Action = unix.FAN_MOVED_FROM

	// FileOrDirMovedFrom event when a file or directory has been moved from the watched directory
	// Requires Linux kernel 5.1 or later (requires FID)
	FileOrDirMovedFrom Action = unix.FAN_MOVED_FROM | unix.FAN_ONDIR

	// FileMovedTo event when a file has been moved to the watched directory
	// Requires Linux kernel 5.1 or later (requires FID)
	FileMovedTo Action = unix.FAN_MOVED_TO

	// FileOrDirMovedTo event when a file or directory has been moved to the watched directory
	// Requires Linux kernel 5.1 or later (requires FID)
	FileOrDirMovedTo Action = unix.FAN_MOVED_TO | unix.FAN_ONDIR

	// WatchedFileMoved event when a watched file has moved
	// Requires Linux kernel 5.1 or later (requires FID)
	WatchedFileMoved Action = unix.FAN_MOVE_SELF

	// WatchedFileOrDirMoved event when a watched file or directory has moved
	// Requires Linux kernel 5.1 or later (requires FID)
	WatchedFileOrDirMoved Action = unix.FAN_MOVE_SELF | unix.FAN_ONDIR
)
