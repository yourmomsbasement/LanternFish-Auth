//go:build windows

package gate

import (
	"syscall"
	"unsafe"
)

var (
	crypt32                = syscall.NewLazyDLL("crypt32.dll")
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procCryptProtectData   = crypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
	procLocalFree          = kernel32.NewProc("LocalFree")
)

const (
	cryptprotectUIForbidden  = 0x1
	cryptprotectLocalMachine = 0x4
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(d []byte) *dataBlob {
	if len(d) == 0 {
		return &dataBlob{}
	}
	return &dataBlob{cbData: uint32(len(d)), pbData: &d[0]}
}

func (b *dataBlob) take() []byte {
	out := make([]byte, b.cbData)
	copy(out, unsafe.Slice(b.pbData, b.cbData))
	procLocalFree.Call(uintptr(unsafe.Pointer(b.pbData)))
	return out
}

// DPAPIAvailable reports whether this build can use Windows DPAPI.
const DPAPIAvailable = true

// DPAPIProtect encrypts data for the current Windows user, or for any account
// on this machine when machine is true.
func DPAPIProtect(data []byte, machine bool) ([]byte, error) {
	flags := uintptr(cryptprotectUIForbidden)
	if machine {
		flags |= cryptprotectLocalMachine
	}
	var out dataBlob
	r, _, err := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(newBlob(data))), 0, 0, 0, 0, flags,
		uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return nil, err
	}
	return out.take(), nil
}

func dpapiUnprotect(blob []byte) ([]byte, error) {
	var out dataBlob
	r, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(newBlob(blob))), 0, 0, 0, 0, cryptprotectUIForbidden,
		uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return nil, err
	}
	return out.take(), nil
}
