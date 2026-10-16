//go:build !unix

package update

import (
	"context"
	"os"
	"time"
)

func openNoFollow(p string) (*os.File, error) {
	if st, err := os.Lstat(p); err == nil && st.Mode()&os.ModeSymlink != 0 {
		return nil, os.ErrPermission
	}
	return os.Open(p)
}

func chownLike(*os.File, os.FileInfo) error { return nil }

// The installer only runs on Linux; elsewhere locking is a no-op.
func lockExclusive(context.Context, string) (func(), error) { return func() {}, nil }

func lockDataFile(string, string, time.Duration) (func(), error) { return func() {}, nil }
