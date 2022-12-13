package fanotify_test

import (
	"log"

	"github.com/opcoder0/fanotify"
)

func ExampleNewListener() {
	if _, err := fanotify.NewNotificationListener("/", true); err != nil {
		log.Fatal("Cannot create listener for mount /", err)
	}
}

func ExampleListener_AddWatch() {
	var listener *fanotify.NotificationListener
	listener, err := fanotify.NewNotificationListener("/", false)
	if err != nil {
		log.Fatal("Cannot create listener for mount /", err)
	}
	listener.AddWatch("/home/user", fanotify.FileModified)
}

func ExampleListener_AddWatch_all() {
	var listener *fanotify.NotificationListener
	var eventTypes fanotify.EventType

	listener, err := fanotify.NewNotificationListener("/", false)
	if err != nil {
		log.Fatal("Cannot create listener for path /", err)
	}
	eventTypes = fanotify.FileAccessed |
		fanotify.FileOrDirectoryAccessed |
		fanotify.FileModified |
		fanotify.FileOpenedForExec |
		fanotify.FileAttribChanged |
		fanotify.FileOrDirectoryAttribChanged |
		fanotify.FileCreated |
		fanotify.FileOrDirectoryCreated |
		fanotify.FileDeleted |
		fanotify.FileOrDirectoryDeleted |
		fanotify.WatchedFileDeleted |
		fanotify.WatchedFileOrDirectoryDeleted |
		fanotify.FileMovedFrom |
		fanotify.FileOrDirectoryMovedFrom |
		fanotify.FileMovedTo |
		fanotify.FileOrDirectoryMovedTo |
		fanotify.WatchedFileMoved |
		fanotify.WatchedFileOrDirectoryMoved
	listener.AddWatch("/home/user", eventTypes)
}
