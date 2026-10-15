package gate

import (
	"errors"
	"os"
	"syscall"
)

const errorSharingViolation syscall.Errno = 32 // ERROR_SHARING_VIOLATION

// lockExclusive opens path with no sharing, so nothing else can open it
// until this handle is closed or the process exits.
func lockExclusive(path string) (*os.File, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(name, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil,
		syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		if errors.Is(err, errorSharingViolation) {
			return nil, errLocked
		}
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}
