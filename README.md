# Fanotify Library

Fanotify library provides a simple API to monitor filesystem for events.

The listener is initialized with flags automatically based on the kernel version. The mark flag features that specify the
the events to monitor a file/directory are validated and checked for valid combinations and validated against the kernel
version.

fanotify has features spanning different kernel versions -

For Linux kernel version 5.0 and earlier no additional information about the underlying filesystem object is available.
For Linux kernel versions 5.1 - 5.8 additional information about the underlying filesystem object is correlated to an event.
For Linux kernel version 5.9 or later the modified file name is made available in the event.

## Example: Listener watching for events

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
        listener, err := fanotify.NewListener(mountPoint)
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

## Tests

Running tests require `CAP_SYS_ADM` privilege. To run the tests make sure to add `go` to the `sudo` PATH.

The command runs all the tests except the ones that test the flag bugs mentioned in the "Known Issues" section above -

```
sudo go test -v
```

To run the tests with flag issues -

```
sudo go test -v -bug
```
