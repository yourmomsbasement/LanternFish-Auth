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
//
// SECURITY: updates are transactional. Update works on a copy and publishes
// it only once it is saved, so a failed save leaves memory and disk agreeing
// (a half-applied revocation used to look done in memory but not on disk).
// Readers never wait for disk I/O: writers are serialised by wmu, and mu is
// held only to take a copy or swap in the new state.
type Store struct {
	path string
	wmu  sync.Mutex   // serialises writers
	mu   sync.RWMutex // guards data
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

// View runs fn with the store locked for reading. fn must not modify d or
// keep pointers into it.
func (s *Store) View(fn func(d *storeData)) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	fn(&s.data)
}

// Update runs fn on a copy of the data and, if fn succeeds, saves the copy
// and makes it current. If fn or the save fails, nothing changes.
func (s *Store) Update(fn func(d *storeData) error) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.mu.RLock()
	next := s.data.clone()
	s.mu.RUnlock()
	if err := fn(&next); err != nil {
		return err
	}
	if err := writeStore(s.path, &next); err != nil {
		return err
	}
	s.mu.Lock()
	s.data = next
	s.mu.Unlock()
	return nil
}

// clone copies the maps and the records in them. Records are replaced, never
// changed in place through shared pointers (time and byte fields are only
// ever reassigned), so copying each struct is enough.
func (d *storeData) clone() storeData {
	c := *d
	c.Devices = make(map[string]*Device, len(d.Devices))
	for k, v := range d.Devices {
		x := *v
		c.Devices[k] = &x
	}
	c.Tickets = make(map[string]*Ticket, len(d.Tickets))
	for k, v := range d.Tickets {
		x := *v
		c.Tickets[k] = &x
	}
	c.AdminKeys = make(map[string]*AdminKey, len(d.AdminKeys))
	for k, v := range d.AdminKeys {
		x := *v
		c.AdminKeys[k] = &x
	}
	return c
}

func (s *Store) save() error { return writeStore(s.path, &s.data) }

// writeStore writes the file atomically with owner-only permissions.
func writeStore(path string, data *storeData) error {
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".gate-*.tmp")
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
	return os.Rename(tmp.Name(), path)
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

// LockFile takes an exclusive lock on the data file for as long as the
// process runs, so two Gates, or a Gate and an offline CLI command, can't
// overwrite each other's changes. It returns a release function.
//
// SECURITY: the lock is held by the operating system (flock on Unix, an
// unshared handle on Windows), so a crashed process releases it and no
// process can take over or remove a lock another one holds. The lock file
// itself is left in place: deleting it would let a second process lock a new
// file while the first still holds the old one.
func LockFile(dataPath string) (func(), error) {
	lock := dataPath + ".lock"
	if err := os.MkdirAll(filepath.Dir(dataPath), 0o700); err != nil {
		return nil, err
	}
	f, err := lockExclusive(lock)
	if errors.Is(err, errLocked) {
		return nil, fmt.Errorf("%s is locked: another lanternfish-gate is using this data file (stop the service before running this command)", lock)
	}
	if err != nil {
		return nil, err
	}
	if err := f.Truncate(0); err == nil {
		fmt.Fprintf(f, "%d\n", os.Getpid())
	}
	return func() { f.Close() }, nil
}

var errLocked = errors.New("lock held by another process")
