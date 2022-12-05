package fanotify

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestNewListenerInvalidFlagClassContent(t *testing.T) {
	var invalidFlag uint
	var eventFlags uint

	invalidFlag = unix.FAN_CLASS_CONTENT | unix.FAN_REPORT_FID
	l, err := newListener("/", invalidFlag, eventFlags, 4096)
	assert.True(t, errors.Is(err, ErrInvalidFlagCombination))
	assert.Nil(t, l)
}

func TestNewListenerInvalidFlagPreClassContent(t *testing.T) {
	var invalidFlag uint
	var eventFlags uint

	invalidFlag = unix.FAN_CLASS_PRE_CONTENT | unix.FAN_REPORT_FID
	l, err := newListener("/", invalidFlag, eventFlags, 4096)
	assert.True(t, errors.Is(err, ErrInvalidFlagCombination))
	assert.Nil(t, l)
}

func TestNewListenerValidFlags(t *testing.T) {
	var flags uint
	var eventFlags uint
	flags = unix.FAN_CLASS_NOTIF | unix.FAN_REPORT_FID
	eventFlags = unix.O_RDONLY | unix.O_LARGEFILE | unix.O_CLOEXEC
	l, err := newListener("/", flags, eventFlags, 4096)
	assert.Nil(t, err)
	assert.NotNil(t, l)
}

// func testKernelVersion(t *testing.T) {
// 	maj, min, patch, err := kernelVersion()
// 	assert.Equal(t, maj, 5)
// 	assert.Equal(t, min, 15)
// 	assert.Equal(t, patch, 0)
// 	assert.Nil(t, err)
// }

func catFile(filename string) (int, error) {
	cmd := exec.Command("cat", filename)
	err := cmd.Run()
	if err != nil {
		return 0, err
	}
	return cmd.Process.Pid, nil
}

func modifyFile(filename string) (int, error) {
	cmd := exec.Command("sed", "-i", "s/\\(.*\\)/\\U\\1/", filename)
	err := cmd.Run()
	if err != nil {
		return 0, err
	}
	return cmd.Process.Pid, nil
}

// TestWithCapSysAdmFanotifyFileAccessed requires CAP_SYS_ADM privilege.
func TestWithCapSysAdmFanotifyFileAccessed(t *testing.T) {
	l, err := NewListener("/", 4096, true)
	assert.Nil(t, err)
	assert.NotNil(t, l)
	watchDir := t.TempDir()
	t.Logf("Watch Directory: %s", watchDir)
	action := FileOrDirectoryAccessed
	l.AddWatch(watchDir, action)
	go l.Start()
	defer l.Stop()
	// generate event
	data := []byte("test data...")
	testFile := fmt.Sprintf("%s/test.dat", watchDir)
	err = os.WriteFile(testFile, data, 0666)
	assert.Nil(t, err)
	t.Logf("Test file created %s", testFile)
	pid, err := catFile(testFile)
	assert.Nil(t, err)
	select {
	case <-time.After(100 * time.Millisecond):
		t.Error("Timeout Error: FileOrDirectoryAccessed event not received")
	case event := <-l.Events:
		assert.Equal(t, fmt.Sprintf("%s/%s", event.Path, event.FileName), testFile)
		assert.Equal(t, event.Pid, pid)
		hasFileAccessed := (event.Mask & FileAccessed) == FileAccessed
		assert.True(t, hasFileAccessed)
	}
}

// TestWithCapSysAdmFanotifyFileModified requires CAP_SYS_ADM privilege.
func TestWithCapSysAdmFanotifyFileModified(t *testing.T) {
	l, err := NewListener("/", 4096, true)
	assert.Nil(t, err)
	assert.NotNil(t, l)
	watchDir := t.TempDir()
	t.Logf("Watch Directory: %s", watchDir)
	action := FileModified
	l.AddWatch(watchDir, action)
	go l.Start()
	defer l.Stop()
	// generate event
	data := []byte("test data...")
	testFile := fmt.Sprintf("%s/test.dat", watchDir)
	err = os.WriteFile(testFile, data, 0666)
	assert.Nil(t, err)
	t.Logf("Test file created %s", testFile)
	pid, err := modifyFile(testFile)
	assert.Nil(t, err)
	select {
	case <-time.After(100 * time.Millisecond):
		t.Error("Timeout Error: FileOrDirectoryAccessed event not received")
	case event := <-l.Events:
		assert.Equal(t, fmt.Sprintf("%s/%s", event.Path, event.FileName), testFile)
		assert.Equal(t, event.Pid, pid)
		isModifed := (event.Mask & FileModified) == FileModified
		assert.True(t, isModifed)
	}
}
