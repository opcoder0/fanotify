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

//
// TestWithCapSysAdm* tests require CAP_SYS_ADM privilege.
// Run tests with sudo or as root -
// sudo go test -v

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

func runAsCmd(args ...string) (int, error) {
	var cmd *exec.Cmd
	if len(args) == 0 {
		return 0, errors.New("missing command name")
	}
	cmdName := args[0]
	cmdArgs := args[1:]
	if len(args) == 1 {
		cmd = exec.Command(cmdName)
	} else {
		cmd = exec.Command(cmdName, cmdArgs...)
	}
	err := cmd.Run()
	if err != nil {
		return 0, err
	}
	return cmd.Process.Pid, nil
}

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
	pid, err := runAsCmd("cat", testFile)
	assert.Nil(t, err)
	select {
	case <-time.After(100 * time.Millisecond):
		t.Error("Timeout Error: FileOrDirectoryAccessed event not received")
	case event := <-l.Events:
		assert.Equal(t, fmt.Sprintf("%s/%s", event.Path, event.FileName), testFile)
		assert.Equal(t, event.Pid, pid)
		assert.True(t, event.Actions.Has(FileAccessed))
	}
}

func TestWithCapSysAdmFanotifyFileModified(t *testing.T) {
	l, err := NewListener("/", 4096, true)
	assert.Nil(t, err)
	assert.NotNil(t, l)
	watchDir := t.TempDir()

	t.Logf("Watch Directory: %s", watchDir)
	data := []byte("test data...")
	testFile := fmt.Sprintf("%s/test.dat", watchDir)
	err = os.WriteFile(testFile, data, 0666)
	assert.Nil(t, err)
	t.Logf("Test file created %s", testFile)
	action := FileModified
	l.AddWatch(watchDir, action)
	go l.Start()
	defer l.Stop()
	pid, err := runAsCmd("touch", "-m", testFile)
	assert.Nil(t, err)
	select {
	case <-time.After(100 * time.Millisecond):
		t.Error("Timeout Error: FileModified event not received")
	case event := <-l.Events:
		assert.Equal(t, fmt.Sprintf("%s/%s", event.Path, event.FileName), testFile)
		assert.Equal(t, event.Pid, pid)
		assert.True(t, event.Actions.Has(FileModified))
	}
}

func TestWithCapSysAdmFanotifyFileClosed(t *testing.T) {
	l, err := NewListener("/", 4096, true)
	assert.Nil(t, err)
	assert.NotNil(t, l)
	watchDir := t.TempDir()

	t.Logf("Watch Directory: %s", watchDir)
	data := []byte("test data...")
	testFile := fmt.Sprintf("%s/test.dat", watchDir)
	err = os.WriteFile(testFile, data, 0666)
	assert.Nil(t, err)
	t.Logf("Test file created %s", testFile)
	action := FileClosed
	l.AddWatch(watchDir, action)
	go l.Start()
	defer l.Stop()
	pid, err := runAsCmd("cat", testFile)
	assert.Nil(t, err)
	select {
	case <-time.After(100 * time.Millisecond):
		t.Error("Timeout Error: FileClosed event not received")
	case event := <-l.Events:
		assert.Equal(t, fmt.Sprintf("%s/%s", event.Path, event.FileName), testFile)
		assert.Equal(t, event.Pid, pid)
		assert.True(t, event.Actions.Has(FileClosedWithNoWrite))
	}
}

func TestWithCapSysAdmFanotifyFileOpen(t *testing.T) {
	l, err := NewListener("/", 4096, true)
	assert.Nil(t, err)
	assert.NotNil(t, l)
	watchDir := t.TempDir()

	t.Logf("Watch Directory: %s", watchDir)
	data := []byte("test data...")
	testFile := fmt.Sprintf("%s/test.dat", watchDir)
	err = os.WriteFile(testFile, data, 0666)
	assert.Nil(t, err)
	t.Logf("Test file created %s", testFile)
	action := FileOpened
	l.AddWatch(watchDir, action)
	go l.Start()
	defer l.Stop()
	pid, err := runAsCmd("cat", testFile)
	assert.Nil(t, err)
	select {
	case <-time.After(100 * time.Millisecond):
		t.Error("Timeout Error: FileOpened event not received")
	case event := <-l.Events:
		assert.Equal(t, fmt.Sprintf("%s/%s", event.Path, event.FileName), testFile)
		assert.Equal(t, event.Pid, pid)
		assert.True(t, event.Actions.Has(FileOpened))
	}
}

func TestWithCapSysAdmFanotifyFileOrDirectoryOpen(t *testing.T) {
	l, err := NewListener("/", 4096, true)
	assert.Nil(t, err)
	assert.NotNil(t, l)
	watchDir := t.TempDir()

	t.Logf("Watch Directory: %s", watchDir)
	action := FileOrDirectoryOpened
	l.AddWatch(watchDir, action)
	go l.Start()
	defer l.Stop()
	pid, err := runAsCmd("ls", watchDir)
	assert.Nil(t, err)
	assert.NotEqual(t, pid, 0)
	select {
	case <-time.After(100 * time.Millisecond):
		t.Error("Timeout Error: FileOrDirectoryOpened event not received")
	case event := <-l.Events:
		assert.Equal(t, fmt.Sprintf("%s/%s", event.Path, event.FileName), fmt.Sprintf("%s/%s", watchDir, "."))
		assert.Equal(t, event.Pid, pid)
		assert.True(t, event.Actions.Has(FileOpened))
	}
}

func TestWithCapSysAdmFanotifyFileOpenForExec(t *testing.T) {
	l, err := NewListener("/", 4096, true)
	assert.Nil(t, err)
	assert.NotNil(t, l)
	watchDir := t.TempDir()

	t.Logf("Watch Directory: %s", watchDir)
	data := []byte(`
#!/bin/bash

echo "test shell script"
exit 0
	`)
	testFile := fmt.Sprintf("%s/test.sh", watchDir)
	err = os.WriteFile(testFile, data, 0755)
	assert.Nil(t, err)
	t.Logf("Test shell script created %s", testFile)
	action := FileOpenedForExec
	l.AddWatch(watchDir, action)
	go l.Start()
	defer l.Stop()
	pid, err := runAsCmd("bash", "-c", testFile)
	assert.Nil(t, err)
	select {
	case <-time.After(100 * time.Millisecond):
		t.Error("Timeout Error: FileOpenedForExec event not received")
	case event := <-l.Events:
		assert.Equal(t, fmt.Sprintf("%s/%s", event.Path, event.FileName), testFile)
		assert.Equal(t, event.Pid, pid)
		assert.True(t, event.Actions.Has(FileOpenedForExec))
	}
}

func TestWithCapSysAdmFanotifyFileAttribChanged(t *testing.T) {
	l, err := NewListener("/", 4096, true)
	assert.Nil(t, err)
	assert.NotNil(t, l)
	watchDir := t.TempDir()

	t.Logf("Watch Directory: %s", watchDir)
	data := []byte(`
#!/bin/bash

echo "test shell script"
exit 0
	`)
	testFile := fmt.Sprintf("%s/test.sh", watchDir)
	err = os.WriteFile(testFile, data, 0666)
	assert.Nil(t, err)
	t.Logf("Test shell script created %s", testFile)
	action := FileAttribChanged
	l.AddWatch(watchDir, action)
	go l.Start()
	defer l.Stop()
	pid, err := runAsCmd("chmod", "+x", testFile)
	assert.Nil(t, err)
	select {
	case <-time.After(100 * time.Millisecond):
		t.Error("Timeout Error: FileOpenedForExec event not received")
	case event := <-l.Events:
		assert.Equal(t, fmt.Sprintf("%s/%s", event.Path, event.FileName), testFile)
		assert.Equal(t, event.Pid, pid)
		assert.True(t, event.Actions.Has(FileAttribChanged))
	}
}

func TestWithCapSysAdmFanotifyFileCreated(t *testing.T) {
	l, err := NewListener("/", 4096, true)
	assert.Nil(t, err)
	assert.NotNil(t, l)
	watchDir := t.TempDir()

	t.Logf("Watch Directory: %s", watchDir)
	action := FileCreated
	l.AddWatch(watchDir, action)
	go l.Start()
	defer l.Stop()
	testFile := fmt.Sprintf("%s/test.txt", watchDir)
	pid, err := runAsCmd("touch", testFile)
	assert.Nil(t, err)
	select {
	case <-time.After(100 * time.Millisecond):
		t.Error("Timeout Error: FileOpenedForExec event not received")
	case event := <-l.Events:
		assert.Equal(t, fmt.Sprintf("%s/%s", event.Path, event.FileName), testFile)
		assert.Equal(t, event.Pid, pid)
		assert.True(t, event.Actions.Has(FileCreated))
	}
}

func TestWithCapSysAdmFanotifyFileOrDirectoryCreated(t *testing.T) {
	l, err := NewListener("/", 4096, true)
	assert.Nil(t, err)
	assert.NotNil(t, l)
	watchDir := t.TempDir()

	t.Logf("Watch Directory: %s", watchDir)
	action := FileOrDirCreated
	l.AddWatch(watchDir, action)
	go l.Start()
	defer l.Stop()
	testDir := fmt.Sprintf("%s/testdir", watchDir)
	pid, err := runAsCmd("mkdir", testDir)
	assert.Nil(t, err)
	select {
	case <-time.After(100 * time.Millisecond):
		t.Error("Timeout Error: FileOpenedForExec event not received")
	case event := <-l.Events:
		assert.Equal(t, fmt.Sprintf("%s/%s", event.Path, event.FileName), testDir)
		assert.Equal(t, event.Pid, pid)
		assert.True(t, event.Actions.Has(FileCreated))
	}
}

func TestWithCapSysAdmFanotifyFileDeleted(t *testing.T) {

	l, err := NewListener("/", 4096, true)
	assert.Nil(t, err)
	assert.NotNil(t, l)

	watchDir := t.TempDir()
	testFile := fmt.Sprintf("%s/test.txt", watchDir)
	pid, err := runAsCmd("touch", testFile)
	assert.Nil(t, err)

	t.Logf("Watch Directory: %s", watchDir)
	action := FileDeleted
	l.AddWatch(watchDir, action)
	go l.Start()
	defer l.Stop()

	pid, err = runAsCmd("rm", "-f", testFile)
	assert.Nil(t, err)
	select {
	case <-time.After(100 * time.Millisecond):
		t.Error("Timeout Error: FileOpenedForExec event not received")
	case event := <-l.Events:
		assert.Equal(t, fmt.Sprintf("%s/%s", event.Path, event.FileName), testFile)
		assert.Equal(t, event.Pid, pid)
		assert.True(t, event.Actions.Has(FileDeleted))
	}
}

func TestWithCapSysAdmFanotifyFileOrDirDeleted(t *testing.T) {

	l, err := NewListener("/", 4096, true)
	assert.Nil(t, err)
	assert.NotNil(t, l)

	watchDir := t.TempDir()
	testDir := fmt.Sprintf("%s/testdir", watchDir)
	pid, err := runAsCmd("mkdir", testDir)
	assert.Nil(t, err)

	t.Logf("Watch Directory: %s", watchDir)
	action := FileOrDirDeleted
	l.AddWatch(watchDir, action)
	go l.Start()
	defer l.Stop()

	pid, err = runAsCmd("rm", "-rf", testDir)
	assert.Nil(t, err)
	select {
	case <-time.After(100 * time.Millisecond):
		t.Error("Timeout Error: FileOpenedForExec event not received")
	case event := <-l.Events:
		assert.Equal(t, fmt.Sprintf("%s/%s", event.Path, event.FileName), testDir)
		assert.Equal(t, event.Pid, pid)
		assert.True(t, event.Actions.Has(FileDeleted))
	}
}

func TestActions(t *testing.T) {
	var actions Action
	actions = FileCreated.Or(FileModified.Or(FileDeleted))
	assert.True(t, actions.Has(FileCreated))
	assert.True(t, actions.Has(FileModified))
	assert.True(t, actions.Has(FileDeleted))
}
