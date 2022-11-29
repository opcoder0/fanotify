package fanotify

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	sizeOfFanotifyEventMetadata = uint32(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
)

// CancelFunc function that allows caller to cancel the running listener.
type CancelFunc func()

var (
	ErrInvalidListener                  = errors.New("invalid listener")
	ErrMountFanReportFid                = errors.New("cannot add mountpoint when FAN_REPORT_FID is set")
	ErrUnsupportedOnKernelVersion       = errors.New("feature unsupported on current kernel version")
	ErrIncompatibleFanotifyStructFormat = errors.New("structures returned at run time must match the structures at compile time")
)

func fanotifyEventOK(meta *unix.FanotifyEventMetadata, n int) bool {
	return (n >= int(sizeOfFanotifyEventMetadata) &&
		meta.Event_len >= sizeOfFanotifyEventMetadata &&
		int(meta.Event_len) <= n)
}

func (l *Listener) fanotifyMark(path string, flags uint, mask uint64) error {
	if l == nil {
		return ErrInvalidListener
	}
	return unix.FanotifyMark(l.fd, flags, mask, -1, path)
}

func (l *Listener) AddDir(dir string, events uint64) error {
	var flags uint
	flags = unix.FAN_MARK_ADD | unix.FAN_MARK_ONLYDIR
	return l.fanotifyMark(dir, flags, events)
}

func (l *Listener) RemoveDir(dir string, events uint64) error {
	var flags uint
	flags = unix.FAN_MARK_REMOVE | unix.FAN_MARK_ONLYDIR
	return l.fanotifyMark(dir, flags, events)
}

func (l *Listener) AddLink(linkName string, events uint64) error {
	var flags uint
	flags = unix.FAN_MARK_ADD | unix.FAN_MARK_DONT_FOLLOW
	return l.fanotifyMark(linkName, flags, events)
}

func (l *Listener) RemoveLink(linkName string, events uint64) error {
	var flags uint
	flags = unix.FAN_MARK_REMOVE | unix.FAN_MARK_DONT_FOLLOW
	return l.fanotifyMark(linkName, flags, events)
}

func (l *Listener) AddFilesystem(path string, events uint64) error {
	if l.kernelMajorVersion < 4 && l.kernelMinorVersion < 20 {
		return ErrUnsupportedOnKernelVersion
	}
	var flags uint
	flags = unix.FAN_MARK_ADD | unix.FAN_MARK_FILESYSTEM
	return l.fanotifyMark(path, flags, events)
}

func (l *Listener) AddPath(path string, events uint64) error {
	return l.fanotifyMark(path, unix.FAN_MARK_ADD, events)
}

func (l *Listener) RemovePath(path string, events uint64) error {
	return l.fanotifyMark(path, unix.FAN_MARK_REMOVE, events)
}

func (l *Listener) RemoveAll() error {
	if l == nil {
		return ErrInvalidListener
	}
	return unix.FanotifyMark(l.fd, unix.FAN_MARK_FLUSH, 0, -1, "")
}

func getFileHandle(metadataLen uint16, buf []byte, i int) *unix.FileHandle {
	var fhSize uint32 // this to uint (this is unsigned int handle_bytes); but go uses uint32
	var fhType int32  // this to int (this is int handle_type); but go uses int32

	sizeOfFanotifyEventInfoHeader := uint32(unsafe.Sizeof(FanotifyEventInfoHeader{}))
	sizeOfKernelFSIDType := uint32(unsafe.Sizeof(kernelFSID{}))
	sizeOfUint32 := uint32(unsafe.Sizeof(fhSize))
	j := uint32(i) + uint32(metadataLen) + sizeOfFanotifyEventInfoHeader + sizeOfKernelFSIDType
	binary.Read(bytes.NewReader(buf[j:j+sizeOfUint32]), binary.LittleEndian, &fhSize)
	j += sizeOfUint32
	binary.Read(bytes.NewReader(buf[j:j+sizeOfUint32]), binary.LittleEndian, &fhType)
	j += sizeOfUint32
	handle := unix.NewFileHandle(fhType, buf[j:j+fhSize])
	return &handle
}

func getFileHandleWithName(metadataLen uint16, buf []byte, i int) (*unix.FileHandle, string) {
	var fhSize uint32
	var fhType int32
	var fname string
	var nameBytes bytes.Buffer

	sizeOfFanotifyEventInfoHeader := uint32(unsafe.Sizeof(FanotifyEventInfoHeader{}))
	sizeOfKernelFSIDType := uint32(unsafe.Sizeof(kernelFSID{}))
	sizeOfUint32 := uint32(unsafe.Sizeof(fhSize))
	j := uint32(i) + uint32(metadataLen) + sizeOfFanotifyEventInfoHeader + sizeOfKernelFSIDType
	binary.Read(bytes.NewReader(buf[j:j+sizeOfUint32]), binary.LittleEndian, &fhSize)
	j += sizeOfUint32
	binary.Read(bytes.NewReader(buf[j:j+sizeOfUint32]), binary.LittleEndian, &fhType)
	j += sizeOfUint32
	handle := unix.NewFileHandle(fhType, buf[j:j+fhSize])
	j += fhSize
	// until we see a nul byte read to get the filename
	for i := j; i < j+unix.NAME_MAX; i++ {
		if buf[i] == 0 {
			break
		}
		nameBytes.WriteByte(buf[i])
	}
	if nameBytes.Len() != 0 {
		fname = nameBytes.String()
	}
	return &handle, fname
}

func (l *Listener) readEvents() error {
	var fid *FanotifyEventInfoFID
	var metadata *unix.FanotifyEventMetadata
	var buf [4096 * sizeOfFanotifyEventMetadata]byte
	var name [unix.PathMax]byte
	var fileHandle *unix.FileHandle
	var fileName string

	for {
		n, err := unix.Read(l.fd, buf[:])
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 || n < int(sizeOfFanotifyEventMetadata) {
			break
		}
		i := 0
		metadata = (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[i]))
		for fanotifyEventOK(metadata, n) {
			if metadata.Vers != unix.FANOTIFY_METADATA_VERSION {
				return ErrIncompatibleFanotifyStructFormat
			}
			fid = (*FanotifyEventInfoFID)(unsafe.Pointer(&buf[i+int(metadata.Metadata_len)]))
			switch l.flagFidType {
			case FanotifyInitFlagFid:
				if fid.Header.InfoType != unix.FAN_EVENT_INFO_TYPE_FID {
					// log.Println("invalid info type header")
					i += int(metadata.Event_len)
					n -= int(metadata.Event_len)
					metadata = (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[i]))
					continue
				}
				fallthrough
			case FanotifyInitFlagDirFid:
				if fid.Header.InfoType != unix.FAN_EVENT_INFO_TYPE_DFID {
					// log.Println("invalid info type header")
					i += int(metadata.Event_len)
					n -= int(metadata.Event_len)
					metadata = (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[i]))
					continue
				}
				fallthrough
			case FanotifyInitFlagReportName:
				if fid.Header.InfoType != unix.FAN_EVENT_INFO_TYPE_DFID_NAME {
					// log.Println("invalid info type header")
					i += int(metadata.Event_len)
					n -= int(metadata.Event_len)
					metadata = (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[i]))
					continue
				}
				fallthrough
			case FanotifyInitFlagDirFidName:
				if fid.Header.InfoType != unix.FAN_EVENT_INFO_TYPE_DFID_NAME {
					// log.Println("invalid info type header")
					i += int(metadata.Event_len)
					n -= int(metadata.Event_len)
					metadata = (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[i]))
					continue
				}
				if fid.Header.InfoType == unix.FAN_EVENT_INFO_TYPE_DFID_NAME {
					fileHandle, fileName = getFileHandleWithName(metadata.Metadata_len, buf[:], i)
					i += len(fileName) // advance some to cover the filename
				} else {
					fileHandle = getFileHandle(metadata.Metadata_len, buf[:], i)
				}
				// TODO converting uintptr to int; Why does Fd() return uintptr and not int
				fd, errno := unix.OpenByHandleAt(int(l.mountpoint.Fd()), *fileHandle, unix.O_RDONLY)
				if errno != nil {
					// log.Println("OpenByHandleAt:", errno)
					i += int(metadata.Event_len)
					n -= int(metadata.Event_len)
					metadata = (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[i]))
					continue
				}
				var pathName string
				// TODO add case for FAN_EVENT_INFO_TYPE_DFID_NAME case where file name is available
				if fid.Header.InfoType != unix.FAN_EVENT_INFO_TYPE_DFID_NAME {
				} else {
					fdPath := fmt.Sprintf("/proc/self/fd/%d", fd)
					n1, _ := unix.Readlink(fdPath, name[:]) // TODO handle err case
					pathName = string(name[:n1])
				}
				event := Event{
					Fd:       fd,
					Path:     pathName,
					FileName: fileName,
					Mask:     metadata.Mask,
				}
				l.Events <- event
			case FanotifyInitFlagNone:
				if metadata.Fd != unix.FAN_NOFD {
					procFdPath := fmt.Sprintf("/proc/self/fd/%d", metadata.Fd)
					n1, err := unix.Readlink(procFdPath, name[:])
					if err != nil {
						// log.Printf("Readlink for path %s failed %v", procFdPath, err)
						continue
					}
					event := Event{
						Fd:   int(metadata.Fd),
						Path: string(name[:n1]),
						Mask: metadata.Mask,
					}
					l.Events <- event
				}
			}
			i += int(metadata.Event_len)
			n -= int(metadata.Event_len)
			metadata = (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[i]))
		}
	}
	return nil
}
