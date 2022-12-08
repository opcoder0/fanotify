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
        listener.AddWatch(listenPath, actions)
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

## Known Issues

Certain flag combinations / actions cause issues with event reporting.

- `fanotify.FileCreated` (`unix.FAN_CREATE`) cannot be or-ed / combined with `fanotify.FileClosed` (`unix.FAN_CLOSE_WRITE` or `unix.FAN_CLOSE_NOWRITE`). The `fanotify` event notification group does not generate any event for this combination.

- Using `fanotify.FileOpened` with any of the actions containing `OrDirectory` (`unix.FAN_ONDIR`) causes an event flood for the directory and then stopping raising any events at all.

- `fanotifyFileOrDirectoryOpened` with any of the other actions causes an event flood for the directory and then stopping raising any events at all.
