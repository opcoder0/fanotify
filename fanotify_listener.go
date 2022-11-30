//go:build linux
// +build linux

package fanotify

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"

	"github.com/syndtr/gocapability/capability"
	"golang.org/x/sys/unix"
)

var (
	// ErrCapSysAdmin indicates caller is missing CAP_SYS_ADMIN permissions
	ErrCapSysAdmin = errors.New("require CAP_SYS_ADMIN capability")
	// ErrInvalidFlagCombination indicates the bit/combination of flags are invalid
	ErrInvalidFlagCombination = errors.New("invalid flag bits")
)

// Event holds the event information for the watched file/directory
type Event struct {
	// Fd is the open file descriptor for the file
	Fd int
	// Path holds the name of the file or the parent directory
	Path string
	// FileName holds the name of the file (available when header info type is FAN_EVENT_INFO_TYPE_DFID_NAME)
	FileName string
	// Mask holds bit mask representing the event
	Mask uint64
}

// Listener represents a fanotify notification group that holds a list of files,
// directories and filesystems under a given mountpoint for which events shall be created.
type Listener struct {
	// fd returned by fanotify_init
	fd int
	// flags passed to fanotify_init
	flags uint
	// mount fd is the file descriptor of the mountpoint
	mountpoint         *os.File
	kernelMajorVersion int
	kernelMinorVersion int
	watches            map[string]bool
	Events             chan Event
}

type fanotifyEventInfoHeader struct {
	InfoType uint8
	pad      uint8
	Len      uint16
}

type kernelFSID struct {
	val [2]int32
}

// FanotifyEventInfoFID represents a unique file identifier info record.
// This structure is used for records of types FAN_EVENT_INFO_TYPE_FID,
// FAN_EVENT_INFO_TYPE_DFID and FAN_EVENT_INFO_TYPE_DFID_NAME.
// For FAN_EVENT_INFO_TYPE_DFID_NAME there is additionally a null terminated
// name immediately after the file handle.
type fanotifyEventInfoFID struct {
	Header     fanotifyEventInfoHeader
	fsid       kernelFSID
	fileHandle byte
}

// returns major, minor, patch version of the kernel
// upon error the string values are empty and the error
// indicates the reason for failure
func kernelVersion() (maj, min, patch int, err error) {
	var sysinfo unix.Utsname
	err = unix.Uname(&sysinfo)
	if err != nil {
		return
	}
	re := regexp.MustCompile(`([0-9]+)`)
	version := re.FindAllString(string(sysinfo.Release[:]), -1)
	if maj, err = strconv.Atoi(version[0]); err != nil {
		return
	}
	if min, err = strconv.Atoi(version[1]); err != nil {
		return
	}
	if patch, err = strconv.Atoi(version[2]); err != nil {
		return
	}
	return maj, min, patch, nil
}

// return true if process has CAP_SYS_ADMIN privilege
// else return false
func checkCapSysAdmin() (bool, error) {
	capabilities, err := capability.NewPid2(os.Getpid())
	if err != nil {
		return false, err
	}
	capabilities.Load()
	capSysAdmin := capabilities.Get(capability.EFFECTIVE, capability.CAP_SYS_ADMIN)
	return capSysAdmin, nil
}

func flagsValid(flags uint) error {
	isSet := func(n, k uint) bool {
		return n&k == k
	}
	if isSet(flags, unix.FAN_REPORT_FID|unix.FAN_CLASS_CONTENT) {
		return errors.New("FAN_REPORT_FID cannot be set with FAN_CLASS_CONTENT")
	}
	if isSet(flags, unix.FAN_REPORT_FID|unix.FAN_CLASS_PRE_CONTENT) {
		return errors.New("FAN_REPORT_FID cannot be set with FAN_CLASS_PRE_CONTENT")
	}
	if isSet(flags, unix.FAN_REPORT_NAME) {
		if !isSet(flags, unix.FAN_REPORT_DIR_FID) {
			return errors.New("FAN_REPORT_NAME must be set with FAN_REPORT_DIR_FID")
		}
	}
	return nil
}

// Check if specified flags are supported for the given
// kernel version. If none of the defined flags are specified
// then the basic option works on any kernel version.
func checkFlagsKernelSupport(flags uint, maj, min int) bool {
	type kernelVersion struct {
		maj int
		min int
	}
	var flagPerKernelVersion = map[uint]kernelVersion{
		unix.FAN_ENABLE_AUDIT:     {4, 15},
		unix.FAN_REPORT_FID:       {5, 1},
		unix.FAN_REPORT_DIR_FID:   {5, 9},
		unix.FAN_REPORT_NAME:      {5, 9},
		unix.FAN_REPORT_DFID_NAME: {5, 9},
	}
	check := func(n, k uint, w, x int) (bool, error) {
		if n&k == k {
			if maj > w {
				return true, nil
			} else if maj == w && min >= x {
				return true, nil
			}
			return false, nil
		}
		return false, errors.New("flag not set")
	}
	for flag, ver := range flagPerKernelVersion {
		if v, err := check(flags, flag, ver.maj, ver.min); err != nil {
			continue // flag not set; check other flags
		} else {
			return v
		}
	}
	// if none of these flags were specified then the basic option
	// works on any kernel version
	return true
}

// NewListener returns a fanotify listener from which events
// can be read. Each listener supports listening to events
// under a single mount point.
//
// For cases where multiple mountpoints need to be monitored
// multiple listener instances need to be used.
//
// NOTE that this call requires CAP_SYS_ADMIN privilege
func NewListener(mountpointPath string, maxEvents uint, withName bool) (*Listener, error) {
	capSysAdmin, err := checkCapSysAdmin()
	if err != nil {
		return nil, err
	}
	if !capSysAdmin {
		return nil, ErrCapSysAdmin
	}
	if maxEvents < 4096 {
		maxEvents = 4096
	}
	var flags, eventFlags uint
	// TODO provide option to specify FAN_REPORT_DIR_FID, FAN_REPORT_NAME + FAN_REPORT_DFID_NAME
	if withName {
		flags = unix.FAN_CLASS_NOTIF | unix.FAN_CLOEXEC | unix.FAN_REPORT_DIR_FID | unix.FAN_REPORT_NAME
	} else {
		flags = unix.FAN_CLASS_NOTIF | unix.FAN_CLOEXEC | unix.FAN_REPORT_FID
	}

	eventFlags = unix.O_RDONLY | unix.O_LARGEFILE | unix.O_CLOEXEC
	return newListener(mountpointPath, flags, eventFlags, maxEvents)
}

func (l *Listener) Start() {
	if len(l.watches) == 0 {
		panic("Nothing to watch. Add Directory/File to the listener to watch")
	}
	var fds [1]unix.PollFd
	fds[0].Fd = int32(l.fd)
	fds[0].Events = unix.POLLIN
	for {
		n, err := unix.Poll(fds[:], -1)
		if n == 0 {
			continue
		}
		if err != nil {
			if err == unix.EINTR {
				continue
			} else {
				// TODO handle error
				return
			}
		}
		l.readEvents() // blocks when the channel bufferred is full
	}
}

func (l *Listener) Close() {
	if l == nil {
		return
	}
	l.mountpoint.Close()
	close(l.Events)
}

func newListener(mountpointPath string, flags, eventFlags, maxEvents uint) (*Listener, error) {
	maj, min, _, err := kernelVersion()
	if err != nil {
		return nil, err
	}
	if err := flagsValid(flags); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidFlagCombination, err)
	}
	if !checkFlagsKernelSupport(flags, maj, min) {
		panic("some of the flags specified are not supported on the current kernel")
	}
	fd, err := unix.FanotifyInit(flags, eventFlags)
	if err != nil {
		return nil, err
	}
	mountpoint, err := os.Open(mountpointPath)
	if err != nil {
		return nil, fmt.Errorf("error opening mountpoint %s: %w", mountpointPath, err)
	}
	listener := &Listener{
		fd:                 fd,
		flags:              flags,
		mountpoint:         mountpoint,
		kernelMajorVersion: maj,
		kernelMinorVersion: min,
		watches:            make(map[string]bool),
		Events:             make(chan Event, maxEvents),
	}
	return listener, nil
}
