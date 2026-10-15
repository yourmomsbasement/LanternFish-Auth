package gate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Device is an enrolled client. PublicKey is the device's SPKI (ECDSA kind);
// SealedSecret is its HMAC secret sealed under the master key (Roku).
type Device struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Platform     string     `json:"platform"`
	Kind         string     `json:"kind"`
	PublicKey    []byte     `json:"public_key,omitempty"`
	SealedSecret string     `json:"sealed_secret,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	EnrolledFrom string     `json:"enrolled_from"`
	LastAuthAt   *time.Time `json:"last_auth_at,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}

func (d *Device) Active() bool { return d != nil && d.RevokedAt == nil }

// Ticket is a pending one-time enrollment ticket. Only its hash is stored.
type Ticket struct {
	ID        string    `json:"id"`
	Hash      string    `json:"hash"`
	Platform  string    `json:"platform"`
	Label     string    `json:"label"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// AdminKey authorises the admin API (for example, Lanternfish Builder).
type AdminKey struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Hash      string     `json:"hash"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

type storeData struct {
	Version     int    `json:"version"`
	KeyCheck    string `json:"key_check"`
	CACertPEM   string `json:"ca_cert_pem"`
	CAKeySealed string `json:"ca_key_sealed"`
	// Key the Gate signs forwarded requests with; Jellyfin's Lanternfish
	// plugin holds only the public half.
	UpstreamPublicKey []byte               `json:"upstream_public_key,omitempty"`
	UpstreamKeySealed string               `json:"upstream_key_sealed,omitempty"`
	Devices           map[string]*Device   `json:"devices"`
	Tickets           map[string]*Ticket   `json:"tickets"`
	AdminKeys         map[string]*AdminKey `json:"admin_keys"`
}

// Store is the Gate's data file. It holds no usable secrets in the clear:
// public keys, hashes, and values sealed under the master key.
type Store struct {
	path string
	mu   sync.Mutex
	data storeData
}

const (
	keyCheckPurpose = "key-check"
	keyCheckValue   = "lanternfish-gate"
	caKeyPurpose    = "device-ca-key"
)

// OpenStore loads the data file, creating it (and the device CA) if missing.
// It refuses to continue if the master key does not match the file.
func OpenStore(path string, sealer *Sealer, now time.Time) (*Store, error) {
	s := &Store{path: path}
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		certPEM, keyDER, err := newDeviceCA(now)
		if err != nil {
			return nil, err
		}
		s.data = storeData{
			Version:     1,
			KeyCheck:    sealer.Seal(keyCheckPurpose, []byte(keyCheckValue)),
			CACertPEM:   string(certPEM),
			CAKeySealed: sealer.Seal(caKeyPurpose, keyDER),
		}
		s.init()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		if err := s.save(); err != nil {
			return nil, err
		}
		return s, nil
	case err != nil:
		return nil, err
	}
	if err := json.Unmarshal(raw, &s.data); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	s.init()
	if v, err := sealer.Open(keyCheckPurpose, s.data.KeyCheck); err != nil || string(v) != keyCheckValue {
		return nil, errors.New("master key does not match the data file")
	}
	return s, nil
}

func (s *Store) init() {
	if s.data.Devices == nil {
		s.data.Devices = map[string]*Device{}
	}
	if s.data.Tickets == nil {
		s.data.Tickets = map[string]*Ticket{}
	}
	if s.data.AdminKeys == nil {
		s.data.AdminKeys = map[string]*AdminKey{}
	}
}

// View runs fn with the store locked for reading.
func (s *Store) View(fn func(d *storeData)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.data)
}

// Update runs fn with the store locked and saves the result if fn succeeds.
func (s *Store) Update(fn func(d *storeData) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(&s.data); err != nil {
		return err
	}
	return s.save()
}

// save writes the file atomically with owner-only permissions.
func (s *Store) save() error {
	raw, err := json.MarshalIndent(&s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".gate-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

func (d *storeData) ticketByHash(hash string) *Ticket {
	for _, t := range d.Tickets {
		if t.Hash == hash {
			return t
		}
	}
	return nil
}

func (d *storeData) adminKeyByHash(hash string) *AdminKey {
	for _, k := range d.AdminKeys {
		if k.Hash == hash && k.RevokedAt == nil {
			return k
		}
	}
	return nil
}

func (d *storeData) pruneTickets(now time.Time) {
	for id, t := range d.Tickets {
		if !now.Before(t.ExpiresAt) {
			delete(d.Tickets, id)
		}
	}
}

// LockFile marks the data file as in use, so offline CLI commands don't race
// a running Gate. With takeOver, an existing lock (left by a crash) is
// replaced instead of refused; the server uses this so it can always restart.
// It returns a release function.
func LockFile(dataPath string, takeOver bool) (func(), error) {
	lock := dataPath + ".lock"
	if err := os.MkdirAll(filepath.Dir(dataPath), 0o700); err != nil {
		return nil, err
	}
	flags := os.O_CREATE | os.O_EXCL | os.O_WRONLY
	if takeOver {
		flags = os.O_CREATE | os.O_TRUNC | os.O_WRONLY
	}
	f, err := os.OpenFile(lock, flags, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("%s exists: stop lanternfish-gate before running this command (delete the lock file if it crashed)", lock)
		}
		return nil, err
	}
	fmt.Fprintf(f, "%d\n", os.Getpid())
	f.Close()
	return func() { os.Remove(lock) }, nil
}
