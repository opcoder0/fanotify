package fanotify

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestNewListenerInvalidFlagClassContent(t *testing.T) {
	var invalidFlag uint
	var eventFlags uint

	invalidFlag = unix.FAN_CLASS_CONTENT | unix.FAN_REPORT_FID
	l, err := newListener("/", invalidFlag, eventFlags, 4096)
	assert.Equal(t, err, ErrInvalidFlagCombination)
	assert.Nil(t, l)
}

func TestNewListenerInvalidFlagPreClassContent(t *testing.T) {
	var invalidFlag uint
	var eventFlags uint

	invalidFlag = unix.FAN_CLASS_PRE_CONTENT | unix.FAN_REPORT_FID
	l, err := newListener("/", invalidFlag, eventFlags, 4096)
	assert.Equal(t, err, ErrInvalidFlagCombination)
	assert.Nil(t, l)
}

func TestNewListenerValidFlags(t *testing.T) {
	var flags uint
	var eventFlags uint

	flags = unix.FAN_CLASS_NOTIF | unix.FAN_REPORT_FID
	l, err := newListener("/", flags, eventFlags, 4096)
	assert.Nil(t, err)
	assert.NotNil(t, l)
}

// skipped
func testKernelVersion(t *testing.T) {
	maj, min, patch, err := kernelVersion()
	assert.Equal(t, maj, 5)
	assert.Equal(t, min, 15)
	assert.Equal(t, patch, 0)
	assert.Nil(t, err)
}
