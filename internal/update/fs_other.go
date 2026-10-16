//go:build !unix

package update

import "os"

func openNoFollow(p string) (*os.File, error) {
	if st, err := os.Lstat(p); err == nil && st.Mode()&os.ModeSymlink != 0 {
		return nil, os.ErrPermission
	}
	return os.Open(p)
}

func chownLike(*os.File, os.FileInfo) error { return nil }
