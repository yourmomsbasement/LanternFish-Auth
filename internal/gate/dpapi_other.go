//go:build !windows

package gate

import "errors"

// DPAPIAvailable reports whether this build can use Windows DPAPI.
const DPAPIAvailable = false

var errNoDPAPI = errors.New("DPAPI is only available on Windows")

func DPAPIProtect([]byte, bool) ([]byte, error) { return nil, errNoDPAPI }

func dpapiUnprotect([]byte) ([]byte, error) { return nil, errNoDPAPI }
