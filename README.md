# Fanotify Library

Fanotify library for Go provides a simple API to monitor filesystem for specific events. The library attempts to simplify specifying events/actions to the watcher by providing valid flag combinations. The flag features are validated against the user's kernel version.

Many of the useful features provided by [fanotify](https://man7.org/linux/man-pages/man7/fanotify.7.html) are available from Linux kernel 5.1 onwards. Most of the useful features availabe through this library work best on kernels 5.1 or later.

## Example: Listener watching for file/directory accessed events

```
package main

import (
        "flag"
        "fmt"
        "os"

        "github.com/opcoder0/fanotify"
)

func main() {
        var listenPath string

        flag.StringVar(&listenPath, "listen-path", "", "path to watch events")
        flag.Parse()

        if listenPath == "" {
                fmt.Println("missing listen path")
                os.Exit(1)
        }
        mountPoint := "/"
        listener, err := fanotify.NewListener(mountPoint, 4096, true)
        if err != nil {
                fmt.Println(err)
                os.Exit(1)
        }
        fmt.Println("Listening to events for:", listenPath)
	var actions Action
	actions =
		fanotify.FileAccessed |
			fanotify.FileOrDirectoryAccessed |
			fanotify.FileModified |
			fanotify.FileOpenedForExec |
			fanotify.FileAttribChanged |
			fanotify.FileOrDirAttribChanged |
			fanotify.FileCreated |
			fanotify.FileOrDirCreated |
			fanotify.FileDeleted |
			fanotify.FileOrDirDeleted |
			fanotify.WatchedFileDeleted |
			fanotify.WatchedFileOrDirDeleted |
			fanotify.FileMovedFrom |
			fanotify.FileOrDirMovedFrom |
			fanotify.FileMovedTo |
			fanotify.FileOrDirMovedTo |
			fanotify.WatchedFileMoved |
			fanotify.WatchedFileOrDirMoved

        listener.AddWatch(listenPath, fanotify.FileOrDirectoryAccessed)
        go listener.Start()
        i := 1
        for event := range listener.Events {
                fmt.Println(event)
                if i == 5 {
                        fmt.Println("Enough events. Stopping...")
                        listener.Stop()
                        break
                }
                i++
        }
}
```
