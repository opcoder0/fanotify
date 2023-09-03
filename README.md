# Fanotify Library

![Fanotify](https://github.com/opcoder0/fanotify/blob/main/images/fanotify.jpeg)

Fanotify library provides a simple API to monitor filesystem for events.

The listener is initialized with flags automatically based on the kernel version. The mark flag features that specify the
the events to monitor a file/directory are validated and checked for valid combinations and validated against the kernel
version.

fanotify has features spanning different kernel versions -

- For Linux kernel version 5.0 and earlier no additional information about the underlying filesystem object is available.
- For Linux kernel versions 5.1 - 5.8 additional information about the underlying filesystem object is correlated to an event.
- For Linux kernel version 5.9 or later the modified file name is made available in the event.

## Examples

Example code for different use-cases can be found here https://github.com/opcoder0/fanotify-examples

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
