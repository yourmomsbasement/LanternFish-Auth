package gate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Device is an enrolled client. PublicKey is the device's SPKI (ECDSA kind);
// SealedSecret is its HMAC secret sealed under the master key (Roku).
type Device struct {
	FactorVerifiedAt   map[string]time.Time `json:"factor_verified_at,omitempty"`
	JellyfinEnrollment *JellyfinEnrollment  `json:"jellyfin_enrollment,omitempty"`
	JellyfinUserID     string               `json:"jellyfin_user_id,omitempty"`
	JellyfinSetupState string               `json:"jellyfin_setup_state,omitempty"`
	ID                 string               `json:"id"`
	Name               string               `json:"name"`
	Platform           string               `json:"platform"`
	Kind               string               `json:"kind"`
	PublicKey          []byte               `json:"public_key,omitempty"`
	SealedSecret       string               `json:"sealed_secret,omitempty"`
	CreatedAt          time.Time            `json:"created_at"`
	EnrolledFrom       string               `json:"enrolled_from"`
	LastAuthAt         *time.Time           `json:"last_auth_at,omitempty"`
	RevokedAt          *time.Time           `json:"revoked_at,omitempty"`
	// SubjectID is the device's owner; ProfileID its assigned policy profile
	// ("" uses the global policy).
	SubjectID string `json:"subject_id,omitempty"`
	ProfileID string `json:"profile_id,omitempty"`
	// Networks are the networks this device is approved to use, newest last.
	Networks []NetworkApproval `json:"networks,omitempty"`

	// Countries are the countries this device has been approved in (geo
	// policy), newest last.
	Countries []CountryApproval `json:"countries,omitempty"`
	// MACs are the interface addresses this device has reported (native
	// clients only), as keyed tags; see mac.go.
	MACs []MACObservation `json:"macs,omitempty"`
	// Suspended: the device must be re-enrolled (e.g. its reported MAC
	// changed under a "reenroll" policy). Unlike revocation, the admin can
	// lift it.
	Suspended string `json:"suspended,omitempty"`
	// Override is an admin-set policy for this device alone, ahead of its
	// profile and the global policy.
	Override *DeviceOverride `json:"override,omitempty"`

	// ParentID is set on a browser key linked to an enrolled device for one
	// application hostname (LinkedHost); see linked.go. It works only while
	// its parent does, only on that host, and under its parent's policy.
	ParentID   string `json:"parent_id,omitempty"`
	LinkedHost string `json:"linked_host,omitempty"`
}

// DeviceOverride points a device at its own policy version for a while.
type DeviceOverride struct {
	PolicyVersion int        `json:"policy_version"`
	Reason        string     `json:"reason"`
	SetBy         string     `json:"set_by"`
	SetAt         time.Time  `json:"set_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
}

// CountryApproval records that a device was approved in a country.
// Country "" (unknown) approvals are bound to the network they were made on.
type CountryApproval struct {
	Country    string    `json:"country"`
	Network    string    `json:"network,omitempty"`
	Method     string    `json:"method"`
	ApprovedAt time.Time `json:"approved_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func (d *Device) Active() bool { return d != nil && d.RevokedAt == nil }

// NetworkApproval lets a device use a network (an address, or the prefix
// around it, depending on the policy that approved it) until ExpiresAt.
type NetworkApproval struct {
	ID            string    `json:"id"`
	Network       string    `json:"network"`
	Method        string    `json:"method"`             // "enrollment", "key_proof", or the factors verified, e.g. "totp+webauthn"
	Verified      bool      `json:"verified,omitempty"` // approved through additional verification
	ApprovedAt    time.Time `json:"approved_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	PolicyVersion int       `json:"policy_version"`
}

// Subject owns devices (and, later, authenticators). Tickets are bound to one.
type Subject struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`   // "owner" or "admin"
	Status    string    `json:"status"` // "active" or "disabled"
	CreatedAt time.Time `json:"created_at"`

	// Factors the owner verifies with. Secrets are sealed; see factors.go.
	TOTP          *TOTPFactor          `json:"totp,omitempty"`
	Passkeys      []WebAuthnCredential `json:"passkeys,omitempty"`
	RecoveryCodes []RecoveryCode       `json:"recovery_codes,omitempty"`
	// JellyfinUserID is an optional, admin-entered mapping; informational.
	JellyfinUserID string `json:"jellyfin_user_id,omitempty"`
}

// Profile is a named policy that devices can be assigned to.
type Profile struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	CreatedAt     time.Time `json:"created_at"`
	PolicyVersion int       `json:"policy_version"`
}

// PolicyRecord is one published, immutable policy version. Scope is "global"
// or a profile ID.
type PolicyRecord struct {
	Version     int       `json:"version"`
	Scope       string    `json:"scope"`
	Policy      Policy    `json:"policy"`
	Editor      string    `json:"editor"`
	Reason      string    `json:"reason"`
	PublishedAt time.Time `json:"published_at"`
}

const (
	defaultSubjectID = "sub_default"
	scopeGlobal      = "global"
)

// Ticket is a pending one-time enrollment ticket. Only its hash is stored.
type Ticket struct {
	JellyfinEnrollment *JellyfinEnrollment `json:"jellyfin_enrollment,omitempty"`
	ID                 string              `json:"id"`
	SubjectID          string              `json:"subject_id,omitempty"`
	ProfileID          string              `json:"profile_id,omitempty"`
	Hash               string              `json:"hash"`
	Platform           string              `json:"platform"`
	Label              string              `json:"label"`
	CreatedBy          string              `json:"created_by"`
	CreatedAt          time.Time           `json:"created_at"`
	ExpiresAt          time.Time           `json:"expires_at"`
	// KeyFingerprint, if set, binds the ticket to one device key: only that
	// key can enroll with it (stops a stolen ticket from being used).
	KeyFingerprint string `json:"key_fingerprint,omitempty"`
}

// AdminKey authorises the admin API (for example, Lanternfish Builder).
type AdminKey struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Hash      string     `json:"hash"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	// Scopes limit what the key may do; nil (keys made before scopes) is
	// every scope. See adminScopes.
	Scopes []string `json:"scopes,omitempty"`
	// SubjectID links the key to an admin owner whose factors protect
	// sensitive dashboard actions (recent verification).
	SubjectID string `json:"subject_id,omitempty"`
}

type storeData struct {
	JellyfinAdmin *JellyfinAdminSettings      `json:"jellyfin_admin,omitempty"`
	EmailSettings *emailSettings              `json:"email_settings,omitempty"`
	Claims        map[string]*EnrollmentClaim `json:"enrollment_claims,omitempty"`
	Version       int                         `json:"version"`
	KeyCheck      string                      `json:"key_check"`
	CACertPEM     string                      `json:"ca_cert_pem"`
	CAKeySealed   string                      `json:"ca_key_sealed"`
	// Key the Gate signs forwarded requests with; Jellyfin's Lanternfish
	// plugin holds only the public half.
	UpstreamPublicKey []byte               `json:"upstream_public_key,omitempty"`
	UpstreamKeySealed string               `json:"upstream_key_sealed,omitempty"`
	Devices           map[string]*Device   `json:"devices"`
	Tickets           map[string]*Ticket   `json:"tickets"`
	AdminKeys         map[string]*AdminKey `json:"admin_keys"`

	// Schema 2: owners, profiles and versioned access policies.
	Subjects            map[string]*Subject `json:"subjects,omitempty"`
	Profiles            map[string]*Profile `json:"profiles,omitempty"`
	GlobalPolicyVersion int                 `json:"global_policy_version,omitempty"`
	LastPolicyVersion   int                 `json:"last_policy_version,omitempty"`
	PolicyHistory       []PolicyRecord      `json:"policy_history,omitempty"`

	// Settings are the network settings changed from the dashboard (nil:
	// everything comes from the environment); see settings.go.
	Settings *GateSettings `json:"settings,omitempty"`
	// Firewall is the dashboard's Proxmox firewall plan (firewall.go).
	Firewall *FirewallPlan `json:"firewall,omitempty"`
}

// maxPolicyHistory bounds stored policy versions; the ones in use are always kept.
const maxPolicyHistory = 500

// Store is the Gate's data file. It holds no usable secrets in the clear:
// public keys, hashes, and values sealed under the master key.
//
// SECURITY: updates are transactional. Update works on a copy and publishes
// it only once it is saved, so a failed save leaves memory and disk agreeing
// (a half-applied revocation used to look done in memory but not on disk).
// Readers never wait for disk I/O: writers are serialised by wmu, and mu is
// held only to take a copy or swap in the new state.
type Store struct {
	readOnly atomic.Bool // refuse every Update (see Gate probation)

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

func (s *Store) init() { s.data.initMaps() }

func (d *storeData) initMaps() {
	if d.Devices == nil {
		d.Devices = map[string]*Device{}
	}
	if d.Tickets == nil {
		d.Tickets = map[string]*Ticket{}
	}
	if d.AdminKeys == nil {
		d.AdminKeys = map[string]*AdminKey{}
	}
	if d.Subjects == nil {
		d.Subjects = map[string]*Subject{}
	}
	if d.Profiles == nil {
		d.Profiles = map[string]*Profile{}
	}
}

// Migrate brings a data file to schema 2: a default owner for existing
// devices and tickets, and the legacy policy (sessions of legacyTTL, no
// network binding, no schedule) as the first global policy, so upgrading
// changes no behaviour until an administrator publishes a policy.
func (s *Store) Migrate(now time.Time, legacyTTL time.Duration) error {
	needed := false
	s.View(func(d *storeData) {
		needed = d.Version < 2 || d.GlobalPolicyVersion == 0 || d.Subjects[defaultSubjectID] == nil
	})
	if !needed {
		return nil
	}
	return s.Update(func(d *storeData) error {
		if d.Subjects[defaultSubjectID] == nil {
			d.Subjects[defaultSubjectID] = &Subject{ID: defaultSubjectID, Name: "Default owner", Role: "owner",
				Status: "active", CreatedAt: now}
		}
		for _, dev := range d.Devices {
			if dev.SubjectID == "" {
				dev.SubjectID = defaultSubjectID
			}
		}
		for _, t := range d.Tickets {
			if t.SubjectID == "" {
				t.SubjectID = defaultSubjectID
			}
		}
		if d.GlobalPolicyVersion == 0 {
			d.publish(scopeGlobal, LegacyPolicy(legacyTTL), "migration", "behaviour before access policies", now)
		}
		d.Version = 2
		return nil
	})
}

// publish records a new immutable policy version for scope and makes it
// current. The caller has validated p.
func (d *storeData) publish(scope string, p Policy, editor, reason string, now time.Time) PolicyRecord {
	p.normalize()
	d.LastPolicyVersion++
	rec := PolicyRecord{Version: d.LastPolicyVersion, Scope: scope, Policy: p, Editor: editor, Reason: reason, PublishedAt: now}
	d.PolicyHistory = append(d.PolicyHistory, rec)
	if scope == scopeGlobal {
		d.GlobalPolicyVersion = rec.Version
	} else if prof := d.Profiles[scope]; prof != nil {
		prof.PolicyVersion = rec.Version
	}
	// Trim old versions, never one that is in use.
	for len(d.PolicyHistory) > maxPolicyHistory {
		inUse := map[int]bool{d.GlobalPolicyVersion: true}
		for _, p := range d.Profiles {
			inUse[p.PolicyVersion] = true
		}
		for _, dev := range d.Devices {
			if dev.Override != nil {
				inUse[dev.Override.PolicyVersion] = true
			}
		}
		trimmed := false
		for i, r := range d.PolicyHistory {
			if !inUse[r.Version] {
				d.PolicyHistory = append(d.PolicyHistory[:i:i], d.PolicyHistory[i+1:]...)
				trimmed = true
				break
			}
		}
		if !trimmed {
			break
		}
	}
	return rec
}

// policyRecord returns the stored policy version, if any.
func (d *storeData) policyRecord(version int) (PolicyRecord, bool) {
	for i := len(d.PolicyHistory) - 1; i >= 0; i-- {
		if d.PolicyHistory[i].Version == version {
			return d.PolicyHistory[i], true
		}
	}
	return PolicyRecord{}, false
}

// ErrProbation is returned by Update while a new version is on probation.
var ErrProbation = errors.New("the Gate is finishing an update; its data can't change until the update is confirmed")

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
	if s.readOnly.Load() {
		return ErrProbation
	}
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

// clone deep-copies the data through JSON, so no nested record (factors,
// approvals, policy documents) is ever shared between the current state and
// the copy being edited. It costs about as much as the save that follows.
func (d *storeData) clone() storeData {
	raw, err := json.Marshal(d)
	if err != nil {
		panic(fmt.Sprintf("store: copy: %v", err)) // every field is plain data
	}
	var c storeData
	if err := json.Unmarshal(raw, &c); err != nil {
		panic(fmt.Sprintf("store: copy: %v", err))
	}
	c.initMaps()
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
