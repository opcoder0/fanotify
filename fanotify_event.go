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

var (
	// ErrNilListener indicates the listener is nil
	ErrNilListener = errors.New("nil listener")
	// ErrUnsupportedOnKernelVersion indicates the feature/flag is unavailable for the current kernel version
	ErrUnsupportedOnKernelVersion = errors.New("feature unsupported on current kernel version")
)

func fanotifyEventOK(meta *unix.FanotifyEventMetadata, n int) bool {
	return (n >= int(sizeOfFanotifyEventMetadata) &&
		meta.Event_len >= sizeOfFanotifyEventMetadata &&
		int(meta.Event_len) <= n)
}

func (l *Listener) fanotifyMark(path string, flags uint, mask uint64, remove bool) error {
	skip := true
	if l == nil {
		return ErrNilListener
	}
	_, found := l.watches[path]
	if found {
		if remove {
			delete(l.watches, path)
			skip = false
		}
	} else {
		if !remove {
			l.watches[path] = true
			skip = false
		}
	}
	if !skip {
		if err := unix.FanotifyMark(l.fd, flags, mask, -1, path); err != nil {
			return err
		}
	}
	return nil
}

func (l *Listener) AddDir(dir string, events uint64) error {
	var flags uint
	flags = unix.FAN_MARK_ADD | unix.FAN_MARK_ONLYDIR
	return l.fanotifyMark(dir, flags, events, false)
}

func (l *Listener) RemoveDir(dir string, events uint64) error {
	var flags uint
	flags = unix.FAN_MARK_REMOVE | unix.FAN_MARK_ONLYDIR
	return l.fanotifyMark(dir, flags, events, true)
}

func (l *Listener) AddLink(linkName string, events uint64) error {
	var flags uint
	flags = unix.FAN_MARK_ADD | unix.FAN_MARK_DONT_FOLLOW
	return l.fanotifyMark(linkName, flags, events, false)
}

func (l *Listener) RemoveLink(linkName string, events uint64) error {
	var flags uint
	flags = unix.FAN_MARK_REMOVE | unix.FAN_MARK_DONT_FOLLOW
	return l.fanotifyMark(linkName, flags, events, true)
}

func (l *Listener) AddFilesystem(path string, events uint64) error {
	if l.kernelMajorVersion < 4 && l.kernelMinorVersion < 20 {
		return ErrUnsupportedOnKernelVersion
	}
	var flags uint
	flags = unix.FAN_MARK_ADD | unix.FAN_MARK_FILESYSTEM
	return l.fanotifyMark(path, flags, events, false)
}

func (l *Listener) AddPath(path string, events uint64) error {
	return l.fanotifyMark(path, unix.FAN_MARK_ADD, events, false)
}

func (l *Listener) RemovePath(path string, events uint64) error {
	return l.fanotifyMark(path, unix.FAN_MARK_REMOVE, events, true)
}

func (l *Listener) RemoveAll() error {
	if l == nil {
		return ErrNilListener
	}
	if err := unix.FanotifyMark(l.fd, unix.FAN_MARK_FLUSH, 0, -1, ""); err != nil {
		return err
	}
	l.watches = make(map[string]bool)
	return nil
}

func getFileHandle(metadataLen uint16, buf []byte, i int) *unix.FileHandle {
	var fhSize uint32 // this is unsigned int handle_bytes; but Go uses uint32
	var fhType int32  // this is int handle_type; but Go uses int32

	sizeOfFanotifyEventInfoHeader := uint32(unsafe.Sizeof(fanotifyEventInfoHeader{}))
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

	sizeOfFanotifyEventInfoHeader := uint32(unsafe.Sizeof(fanotifyEventInfoHeader{}))
	sizeOfKernelFSIDType := uint32(unsafe.Sizeof(kernelFSID{}))
	sizeOfUint32 := uint32(unsafe.Sizeof(fhSize))
	j := uint32(i) + uint32(metadataLen) + sizeOfFanotifyEventInfoHeader + sizeOfKernelFSIDType
	binary.Read(bytes.NewReader(buf[j:j+sizeOfUint32]), binary.LittleEndian, &fhSize)
	j += sizeOfUint32
	binary.Read(bytes.NewReader(buf[j:j+sizeOfUint32]), binary.LittleEndian, &fhType)
	j += sizeOfUint32
	handle := unix.NewFileHandle(fhType, buf[j:j+fhSize])
	j += fhSize
	// stop when NULL byte is read to get the filename
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
	var fid *fanotifyEventInfoFID
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
				panic("metadata structure from the kernel does not match the structure definition at compile time")
			}
			if metadata.Fd != unix.FAN_NOFD {
				// no fid
				procFdPath := fmt.Sprintf("/proc/self/fd/%d", metadata.Fd)
				n1, err := unix.Readlink(procFdPath, name[:])
				if err != nil {
					i += int(metadata.Event_len)
					n -= int(metadata.Event_len)
					metadata = (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[i]))
					continue
				}
				event := Event{
					Fd:   int(metadata.Fd),
					Path: string(name[:n1]),
					Mask: metadata.Mask,
				}
				l.Events <- event

			} else {
				// fid
				fid = (*fanotifyEventInfoFID)(unsafe.Pointer(&buf[i+int(metadata.Metadata_len)]))
				withName := false
				switch {
				case fid.Header.InfoType == unix.FAN_EVENT_INFO_TYPE_FID:
					withName = false
				case fid.Header.InfoType == unix.FAN_EVENT_INFO_TYPE_DFID:
					withName = false
				case fid.Header.InfoType == unix.FAN_EVENT_INFO_TYPE_DFID_NAME:
					withName = true
				default:
					i += int(metadata.Event_len)
					n -= int(metadata.Event_len)
					metadata = (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[i]))
					continue
				}
				if withName {
					fileHandle, fileName = getFileHandleWithName(metadata.Metadata_len, buf[:], i)
					i += len(fileName) // advance some to cover the filename
				} else {
					fileHandle = getFileHandle(metadata.Metadata_len, buf[:], i)
				}
				fd, errno := unix.OpenByHandleAt(int(l.mountpoint.Fd()), *fileHandle, unix.O_RDONLY)
				if errno != nil {
					// log.Println("OpenByHandleAt:", errno)
					i += int(metadata.Event_len)
					n -= int(metadata.Event_len)
					metadata = (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[i]))
					continue
				}
				fdPath := fmt.Sprintf("/proc/self/fd/%d", fd)
				n1, _ := unix.Readlink(fdPath, name[:]) // TODO handle err case
				pathName := string(name[:n1])
				event := Event{
					Fd:       fd,
					Path:     pathName,
					FileName: fileName,
					Mask:     metadata.Mask,
				}
				l.Events <- event
				i += int(metadata.Event_len)
				n -= int(metadata.Event_len)
				metadata = (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[i]))
			}
		}
	}
	return nil
}
