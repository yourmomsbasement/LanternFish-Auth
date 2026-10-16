package gate

import (
	"crypto/x509"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Admin performs offline maintenance on the data file (CLI commands).
type Admin struct {
	cfg   Config
	store *Store
	audit *auditLog
}

func OpenAdmin(cfg Config) (*Admin, error) {
	cfg.setDefaults()
	sealer, err := NewSealer(cfg.MasterKey)
	if err != nil {
		return nil, err
	}
	store, err := OpenStore(cfg.DataPath, sealer, cfg.Now())
	if err != nil {
		return nil, err
	}
	if err := store.Migrate(cfg.Now(), cfg.SessionTTL); err != nil {
		return nil, fmt.Errorf("upgrade data file: %w", err)
	}
	audit, err := openAuditLog(cfg.AuditPath)
	if err != nil {
		return nil, err
	}
	return &Admin{cfg: cfg, store: store, audit: audit}, nil
}

// CreateAdminKey returns the new key's ID and its value, which is not stored.
func (a *Admin) CreateAdminKey(name string, scopes ...string) (id, key string, err error) {
	now := a.cfg.Now()
	key = "lfa_" + randomToken()
	k := &AdminKey{ID: newID("adm_"), Name: cleanName(name), Hash: hashToken(key), CreatedAt: now}
	if len(scopes) > 0 {
		for _, s := range scopes {
			if !contains(allScopes, s) {
				return "", "", fmt.Errorf("unknown scope %q (have: %s)", s, strings.Join(allScopes, ", "))
			}
		}
		k.Scopes = scopes
	}
	if err := a.store.Update(func(d *storeData) error {
		d.AdminKeys[k.ID] = k
		return nil
	}); err != nil {
		return "", "", err
	}
	a.audit.write(now, "admin_key_created", map[string]any{"admin_key_id": k.ID, "name": k.Name})
	return k.ID, key, nil
}

func (a *Admin) AdminKeys() []AdminKey {
	var out []AdminKey
	a.store.View(func(d *storeData) {
		for _, k := range d.AdminKeys {
			out = append(out, *k)
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// AllScopes lists the admin key scopes.
func AllScopes() []string { return append([]string(nil), allScopes...) }

// LinkAdminKey links a key to an admin-role owner (or unlinks with "").
func (a *Admin) LinkAdminKey(id, subjectID string) error {
	return a.store.Update(func(d *storeData) error {
		k := d.AdminKeys[id]
		if k == nil {
			return errors.New("no such admin key")
		}
		if s := d.Subjects[subjectID]; subjectID != "" && (s == nil || s.Role != "admin") {
			return errors.New("link to an owner with the admin role")
		}
		k.SubjectID = subjectID
		return nil
	})
}

// SubjectSummary is an owner and their factors, for the CLI.
type SubjectSummary struct {
	ID, Name, Role, Status string
	TOTP                   bool
	Passkeys, Recovery     int
}

func (a *Admin) Subjects() []SubjectSummary {
	var out []SubjectSummary
	a.store.View(func(d *storeData) {
		for _, s := range d.Subjects {
			n := 0
			for _, rc := range s.RecoveryCodes {
				if rc.UsedAt == nil {
					n++
				}
			}
			out = append(out, SubjectSummary{s.ID, s.Name, s.Role, s.Status, s.TOTP != nil, len(s.Passkeys), n})
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ResetFactors is the local break-glass recovery: it removes an owner's
// authenticator app, passkeys and recovery codes, so new ones can be set up
// with a setup link. It runs only offline (the Gate stopped, the data file
// locked), which also ends every admin session.
func (a *Admin) ResetFactors(subjectID string) error {
	now := a.cfg.Now()
	err := a.store.Update(func(d *storeData) error {
		s := d.Subjects[subjectID]
		if s == nil {
			return errors.New("no such owner")
		}
		s.TOTP, s.Passkeys, s.RecoveryCodes = nil, nil, nil
		return nil
	})
	if err == nil {
		a.audit.write(now, "factors_reset_offline", map[string]any{"subject_id": subjectID})
	}
	return err
}

func (a *Admin) RevokeAdminKey(id string) error {
	now := a.cfg.Now()
	err := a.store.Update(func(d *storeData) error {
		k, ok := d.AdminKeys[id]
		if !ok {
			return errors.New("no such admin key")
		}
		if k.RevokedAt == nil {
			t := now
			k.RevokedAt = &t
		}
		return nil
	})
	if err == nil {
		a.audit.write(now, "admin_key_revoked", map[string]any{"admin_key_id": id})
	}
	return err
}

func (a *Admin) DeviceCACertPEM() []byte {
	var out []byte
	a.store.View(func(d *storeData) { out = []byte(d.CACertPEM) })
	return out
}

// UpstreamPublicKey returns the base64 key for the Jellyfin plugin, creating
// the signing key if this data file does not have one yet.
func (a *Admin) UpstreamPublicKey() (string, error) {
	sealer, err := NewSealer(a.cfg.MasterKey)
	if err != nil {
		return "", err
	}
	key, err := loadUpstreamKey(a.store, sealer)
	if err != nil {
		return "", err
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", err
	}
	return encodeB64(pub), nil
}
