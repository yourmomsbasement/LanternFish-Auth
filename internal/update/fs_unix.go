//go:build unix

package update

import (
	"os"
	"syscall"
)

func openNoFollow(p string) (*os.File, error) {
	return os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

// chownLike gives f the owner and group of prev (when running as root).
func chownLike(f *os.File, prev os.FileInfo) error {
	st, ok := prev.Sys().(*syscall.Stat_t)
	if !ok || os.Geteuid() != 0 {
		return nil
	}
	return f.Chown(int(st.Uid), int(st.Gid))
}
