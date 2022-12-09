// Package fanotify library provides a simple API to monitor filesystem for events.
//
// The listener is initialized with flags automatically based on the kernel version. The mark flag features that specify the
// the events to monitor a file/directory are validated and checked for valid combinations and validated against the kernel
// version.
//
// fanotify system has features spanning different kernel versions:
//   - For Linux kernel version 5.0 and earlier no additional information about the underlying filesystem object is available.
//   - For Linux kernel versions 5.1 to 5.8 additional information about the underlying filesystem object is correlated to an event.
//   - For Linux kernel version 5.9 or later the modified file name is made available in the event.
//
package fanotify
