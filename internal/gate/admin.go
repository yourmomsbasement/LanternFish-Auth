package gate

import (
	"errors"
	"sort"
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
	audit, err := openAuditLog(cfg.AuditPath)
	if err != nil {
		return nil, err
	}
	return &Admin{cfg: cfg, store: store, audit: audit}, nil
}

// CreateAdminKey returns the new key's ID and its value, which is not stored.
func (a *Admin) CreateAdminKey(name string) (id, key string, err error) {
	now := a.cfg.Now()
	key = "lfa_" + randomToken()
	k := &AdminKey{ID: newID("adm_"), Name: cleanName(name), Hash: hashToken(key), CreatedAt: now}
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
