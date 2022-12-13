# Fanotify Library

Fanotify library provides a simple API to monitor filesystem for events.

The listener is initialized with flags automatically based on the kernel version. The mark flag features that specify the
the events to monitor a file/directory are validated and checked for valid combinations and validated against the kernel
version.

fanotify has features spanning different kernel versions -

- For Linux kernel version 5.0 and earlier no additional information about the underlying filesystem object is available.
- For Linux kernel versions 5.1 - 5.8 additional information about the underlying filesystem object is correlated to an event.
- For Linux kernel version 5.9 or later the modified file name is made available in the event.

## Example: Listener watching for events on a directory

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
	listener, err := fanotify.NewListener(mountPoint, false, fanotify.PermissionNone)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("Listening to events for:", listenPath)
	var eventTypes EventType
	eventTypes =
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
	listener.AddWatch(listenPath, eventTypes)
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

## Example: Listener watching for events on a mount point

```
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/opcoder0/fanotify"
)

func main() {
	var mountPoint string

	flag.StringVar(&mountPoint, "mount-path", "", "mount point path")
	flag.Parse()

	if mountPoint == "" {
		fmt.Println("missing mount path")
		os.Exit(1)
	}
	listener, err := fanotify.NewListener(mountPoint, true, fanotify.PermissionNone)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("Listening to events for:", mountPoint)
	var eventTypes fanotify.EventType
	eventTypes = fanotify.FileAccessed |
	                fanotify.FileOrDirectoryAccessed |
			fanotify.FileModified |
			fanotify.FileClosedAfterWrite |
			fanotify.FileClosedWithNoWrite |
			fanotify.FileOpened |
			fanotify.FileOrDirectoryOpened |
			fanotify.FileOpenedForExec
	err = listener.MarkMount(eventTypes, false)
	if err != nil {
		fmt.Println("MarkMount:", err)
		os.Exit(1)
	}
	go listener.Start()
	for event := range listener.Events {
		fmt.Println(event)
	}
	listener.Stop()
}
```
## Known Issues

Certain flag combinations / event types cause issues with event reporting.

- `fanotify.FileCreated` cannot be or-ed / combined with `fanotify.FileClosed`. The `fanotify` event notification group does not generate any event for this combination.
- Using `fanotify.FileOpened` with any of the event types containing `OrDirectory` causes numerous duplicate events for the path.
- `fanotifyFileOrDirectoryOpened` with any of the other event types causes numerous duplicate events for the path.

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
