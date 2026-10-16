//go:build unix

package update

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"
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

// lockExclusive takes an exclusive lock on p, waiting for it (until ctx is
// done). It returns the release function.
func lockExclusive(ctx context.Context, p string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { f.Close() }, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			f.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// lockDataFile takes the Gate's own data lock (the one a running Gate and
// the offline commands hold), waiting up to wait. A lock file it has to
// create gets the data file's owner, so the Gate can still open it.
func lockDataFile(lockPath, dataPath string, wait time.Duration) (func(), error) {
	created := false
	f, err := os.OpenFile(lockPath, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		f, err = os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
		created = err == nil
	}
	if err != nil {
		return nil, err
	}
	if created {
		if st, err := os.Lstat(dataPath); err == nil {
			chownLike(f, st)
		}
	}
	deadline := time.Now().Add(wait)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { f.Close() }, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) || time.Now().After(deadline) {
			f.Close()
			return nil, err
		}
		time.Sleep(200 * time.Millisecond)
	}
}
