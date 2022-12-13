package fanotify

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var bug = flag.Bool("bug", false, "run fanotify flag bug tests")

//
// TestWithCapSysAdm* tests require CAP_SYS_ADM privilege.
// Run tests with sudo or as root -
// sudo go test -v

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
	l, err := NewNotificationListener("/", false)
	assert.Nil(t, err)
	assert.NotNil(t, l)
	watchDir := t.TempDir()
	t.Logf("Watch Directory: %s", watchDir)
	eventType := FileOrDirectoryAccessed
	l.AddWatch(watchDir, eventType)
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
		assert.True(t, event.EventTypes.Has(FileAccessed))
	}
}

func TestWithCapSysAdmFanotifyFileModified(t *testing.T) {
	l, err := NewNotificationListener("/", false)
	assert.Nil(t, err)
	assert.NotNil(t, l)
	watchDir := t.TempDir()

	t.Logf("Watch Directory: %s", watchDir)
	data := []byte("test data...")
	testFile := fmt.Sprintf("%s/test.dat", watchDir)
	err = os.WriteFile(testFile, data, 0666)
	assert.Nil(t, err)
	t.Logf("Test file created %s", testFile)
	eventType := FileModified
	l.AddWatch(watchDir, eventType)
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
		assert.True(t, event.EventTypes.Has(FileModified))
	}
}

func TestWithCapSysAdmFanotifyFileClosed(t *testing.T) {
	l, err := NewNotificationListener("/", false)
	assert.Nil(t, err)
	assert.NotNil(t, l)
	watchDir := t.TempDir()

	t.Logf("Watch Directory: %s", watchDir)
	data := []byte("test data...")
	testFile := fmt.Sprintf("%s/test.dat", watchDir)
	err = os.WriteFile(testFile, data, 0666)
	assert.Nil(t, err)
	t.Logf("Test file created %s", testFile)
	eventType := FileClosed
	l.AddWatch(watchDir, eventType)
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
		assert.True(t, event.EventTypes.Has(FileClosedWithNoWrite))
	}
}

func TestWithCapSysAdmFanotifyFileOpen(t *testing.T) {
	l, err := NewNotificationListener("/", false)
	assert.Nil(t, err)
	assert.NotNil(t, l)
	watchDir := t.TempDir()

	t.Logf("Watch Directory: %s", watchDir)
	data := []byte("test data...")
	testFile := fmt.Sprintf("%s/test.dat", watchDir)
	err = os.WriteFile(testFile, data, 0666)
	assert.Nil(t, err)
	t.Logf("Test file created %s", testFile)
	eventType := FileOpened
	l.AddWatch(watchDir, eventType)
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
		assert.True(t, event.EventTypes.Has(FileOpened))
	}
}

func TestWithCapSysAdmFanotifyFileOrDirectoryOpen(t *testing.T) {
	l, err := NewNotificationListener("/", false)
	assert.Nil(t, err)
	assert.NotNil(t, l)
	watchDir := t.TempDir()

	t.Logf("Watch Directory: %s", watchDir)
	eventType := FileOrDirectoryOpened
	l.AddWatch(watchDir, eventType)
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
		assert.True(t, event.EventTypes.Has(FileOpened))
	}
}

func TestWithCapSysAdmFanotifyFileOpenForExec(t *testing.T) {
	l, err := NewNotificationListener("/", false)
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
	eventType := FileOpenedForExec
	l.AddWatch(watchDir, eventType)
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
		assert.True(t, event.EventTypes.Has(FileOpenedForExec))
	}
}

func TestWithCapSysAdmFanotifyFileAttribChanged(t *testing.T) {
	l, err := NewNotificationListener("/", false)
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
	eventType := FileAttribChanged
	l.AddWatch(watchDir, eventType)
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
		assert.True(t, event.EventTypes.Has(FileAttribChanged))
	}
}

func TestWithCapSysAdmFanotifyFileCreated(t *testing.T) {
	l, err := NewNotificationListener("/", false)
	assert.Nil(t, err)
	assert.NotNil(t, l)
	watchDir := t.TempDir()

	t.Logf("Watch Directory: %s", watchDir)
	eventType := FileCreated
	l.AddWatch(watchDir, eventType)
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
		assert.True(t, event.EventTypes.Has(FileCreated))
	}
}

func TestWithCapSysAdmFanotifyFileOrDirectoryCreated(t *testing.T) {
	l, err := NewNotificationListener("/", false)
	assert.Nil(t, err)
	assert.NotNil(t, l)
	watchDir := t.TempDir()

	t.Logf("Watch Directory: %s", watchDir)
	eventType := FileOrDirectoryCreated
	l.AddWatch(watchDir, eventType)
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
		assert.True(t, event.EventTypes.Has(FileCreated))
	}
}

func TestWithCapSysAdmFanotifyFileDeleted(t *testing.T) {

	l, err := NewNotificationListener("/", false)
	assert.Nil(t, err)
	assert.NotNil(t, l)

	watchDir := t.TempDir()
	testFile := fmt.Sprintf("%s/test.txt", watchDir)
	pid, err := runAsCmd("touch", testFile)
	assert.Nil(t, err)

	t.Logf("Watch Directory: %s", watchDir)
	eventType := FileDeleted
	l.AddWatch(watchDir, eventType)
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
		assert.True(t, event.EventTypes.Has(FileDeleted))
	}
}

func TestWithCapSysAdmFanotifyFileOrDirectoryDeleted(t *testing.T) {

	l, err := NewNotificationListener("/", false)
	assert.Nil(t, err)
	assert.NotNil(t, l)

	watchDir := t.TempDir()
	testDir := fmt.Sprintf("%s/testdir", watchDir)
	pid, err := runAsCmd("mkdir", testDir)
	assert.Nil(t, err)

	t.Logf("Watch Directory: %s", watchDir)
	eventType := FileOrDirectoryDeleted
	l.AddWatch(watchDir, eventType)
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
		assert.True(t, event.EventTypes.Has(FileDeleted))
	}
}

func TestEventTypes(t *testing.T) {
	var eventTypes EventType
	eventTypes = FileCreated.Or(FileModified.Or(FileDeleted))
	assert.True(t, eventTypes.Has(FileCreated))
	assert.True(t, eventTypes.Has(FileModified))
	assert.True(t, eventTypes.Has(FileDeleted))
}

func TestMultipleEvents(t *testing.T) {
	l, err := NewNotificationListener("/", false)
	assert.Nil(t, err)
	assert.NotNil(t, l)
	go l.Start()
	defer l.Stop()

	watchDir := t.TempDir()
	eventTypes := FileOrDirectoryCreated.Or(FileModified.Or(FileDeleted))
	l.AddWatch(watchDir, eventTypes)
	testFile := fmt.Sprintf("%s/test.txt", watchDir)
	pid, err := runAsCmd("touch", testFile) // create file
	assert.Nil(t, err)
	select {
	case <-time.After(100 * time.Millisecond):
		t.Error("Timeout Error: FileCreated event not received")
	case event := <-l.Events:
		assert.Equal(t, fmt.Sprintf("%s/%s", event.Path, event.FileName), testFile)
		assert.Equal(t, event.Pid, pid)
		assert.True(t, event.EventTypes.Has(FileCreated))
		t.Logf("Received: (%s)", event)
	}
	touchPid := pid

	// modify file
	os.WriteFile(testFile, []byte("test string"), 0666)
	pid = os.Getpid()
	select {
	case <-time.After(100 * time.Millisecond):
		t.Error("Timeout Error: FileModified event not received")
	case event := <-l.Events:
		assert.Equal(t, fmt.Sprintf("%s/%s", event.Path, event.FileName), testFile)
		assert.Equal(t, event.Pid, pid)
		assert.True(t, event.EventTypes.Has(FileModified))
		t.Logf("Received: (%s)", event)
	}

	t.Logf("Pids: Self(%d), Touch(%d)", pid, touchPid)
	// NOTE: os.WriteFile sends two modify events; so draining them
	for len(l.Events) > 0 {
		e := <-l.Events
		t.Logf("Drain-Event: (%s)", e)
	}
	pid, err = runAsCmd("rm", "-f", testFile)
	assert.Nil(t, err)
	select {
	case <-time.After(100 * time.Millisecond):
		t.Error("Timeout Error: FileDeleted event not received")
	case event := <-l.Events:
		assert.Equal(t, fmt.Sprintf("%s/%s", event.Path, event.FileName), testFile)
		assert.Equal(t, event.Pid, pid)
		assert.True(t, event.EventTypes.Has(FileDeleted))
		t.Logf("Received: (%s)", event)
	}
}

// FileCreated and FileClosed combination does not raise any events
func TestWithCapSysAdmMarkCreateCloseBug(t *testing.T) {
	if *bug {
		l, err := NewNotificationListener("/", false)
		assert.Nil(t, err)
		assert.NotNil(t, l)
		go l.Start()
		defer l.Stop()

		watchDir := t.TempDir()
		eventTypes := FileCreated.Or(FileClosed)
		l.AddWatch(watchDir, eventTypes)
		testFile := fmt.Sprintf("%s/test.txt", watchDir)
		pid, err := runAsCmd("touch", testFile) // create file
		assert.Nil(t, err)
		select {
		case <-time.After(100 * time.Millisecond):
			t.Log("BUG: no events after file create", "confirmed that no events are raised if mark contains unix.FAN_CREATE|unix.FAN_CLOSE")
		case event := <-l.Events:
			assert.Equal(t, fmt.Sprintf("%s/%s", event.Path, event.FileName), testFile)
			assert.Equal(t, event.Pid, pid)
			t.Logf("Received: (%s)", event)
		}

		// cat the file to simulate close after read
		pid, err = runAsCmd("cat", testFile)
		assert.Nil(t, err)
		select {
		case <-time.After(100 * time.Millisecond):
			assert.Fail(t, "BUG: no events after file close", "confirmed that no events are raised if mark contains unix.FAN_CREATE|unix.FAN_CLOSE")
		case event := <-l.Events:
			assert.Equal(t, fmt.Sprintf("%s/%s", event.Path, event.FileName), testFile)
			assert.Equal(t, event.Pid, pid)
			t.Logf("Received: (%s)", event)
		}
	} else {
		t.Skip()
	}
}

// FileCreated and FileClosed combination does not raise any events
func TestWithCapSysAdmMarkFileOrDirectoryOpenedBug(t *testing.T) {

	if *bug {
		// setup the file for modification
		watchDir := t.TempDir()
		testFile := fmt.Sprintf("%s/test.txt", watchDir)
		_, err := runAsCmd("touch", testFile) // create file
		assert.Nil(t, err)

		// start the listener
		l, err := NewNotificationListener("/", false)
		assert.Nil(t, err)
		assert.NotNil(t, l)
		go l.Start()
		defer l.Stop()
		var eventTypes EventType
		eventTypes =
			FileAccessed |
				FileOrDirectoryAccessed |
				FileModified |
				FileOpenedForExec |
				FileAttribChanged |
				FileOrDirectoryAttribChanged |
				FileCreated |
				FileOrDirectoryCreated |
				FileDeleted |
				FileOrDirectoryDeleted |
				WatchedFileDeleted |
				WatchedFileOrDirectoryDeleted |
				FileMovedFrom |
				FileOrDirectoryMovedFrom |
				FileMovedTo |
				FileOrDirectoryMovedTo |
				WatchedFileMoved |
				WatchedFileOrDirectoryMoved |
				FileOrDirectoryOpened
		l.AddWatch(watchDir, eventTypes)

		// cat the file to simulate close after read
		_, err = runAsCmd("cat", testFile)
		assert.Nil(t, err)
		n := 0
		for len(l.Events) > 0 {
			e := <-l.Events
			t.Logf("drain-event: %v", e)
			n++
		}
		t.Logf("BUG: received %d events; while cat would otherwise raise 1 FileAccessed event", n)

		// BUG more duplicate flood events or no further events are received past this
		// attribute change file
		pid, err := runAsCmd("chmod", "+x", testFile)
		assert.Nil(t, err)
		select {
		case <-time.After(100 * time.Millisecond):
			assert.Fail(t, "BUG: no events after chmod", "no events after the duplicate event flood")
		case event := <-l.Events:
			assert.Equal(t, fmt.Sprintf("%s/%s", event.Path, event.FileName), testFile)
			assert.Equal(t, event.Pid, pid)
			assert.True(t, event.EventTypes.Has(FileAttribChanged))
			t.Logf("Received event: (%s)", event)
		}
	} else {
		t.Skip()
	}
}

func TestIsFanotifyIsFanotifyPermissionMarkValid(t *testing.T) {
	type test struct {
		mask  EventType
		valid bool
	}
	tests := []test{
		{
			FileOpenPermission,
			true,
		},
		{
			FileOpenPermission.Or(FileOpenToExecutePermission),
			true,
		},
		{
			FileOpenPermission.Or(FileOpenToExecutePermission.Or(FileAccessPermission)),
			true,
		},
		{
			FileOpenPermission.Or(FileOpenToExecutePermission.Or(FileMovedTo)),
			false,
		},
	}
	for _, tc := range tests {
		err := isFanotifyPermissionMarkValid(uint64(tc.mask))
		if tc.valid {
			assert.Nil(t, err)
		} else {
			assert.NotNil(t, err)
		}
	}
}
