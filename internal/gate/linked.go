package gate

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Applications on other hostnames: linking a browser.
//
// A browser's device key lives in one origin's storage, and its session
// cookie is sent to one host. On an application's hostname the browser has
// neither, so it is sent to the sign-in host (Jellyfin's), where it signs in
// with its key as usual, policy and additional verification included. There
// it asks for a link code for the application's host and returns with the
// code in the URL fragment. The page there creates a key for that origin and
// redeems the code with it: the Gate records the key as a *linked* device
// of the browser's device.
//
// SECURITY: a linked device
//   - works only while its parent does: revoking, suspending or resetting
//     the parent (or disabling its owner) stops it too (activeDevice);
//   - works only on the host it was linked for;
//   - follows its parent's owner, profile and own policy;
//   - comes from a code that is single use, lives 2 minutes, names one
//     application host, and is redeemed from the address it was issued to.
//
// The code travels only in fragments, which browsers never send to servers.

const (
	linkContext = "lanternfish-gate/v2/link\n"
	linkCodeTTL = 2 * time.Minute
)

func linkMessage(code string) []byte { return []byte(linkContext + code) }

type linkCode struct {
	parentID string
	host     string
	ip       string
	expires  time.Time
}

type linkTable struct {
	mu    sync.Mutex
	codes map[string]linkCode // by code hash
}

func (t *linkTable) put(c linkCode, now time.Time) string {
	code := "lfl_" + randomToken()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.codes == nil {
		t.codes = map[string]linkCode{}
	}
	for k, v := range t.codes {
		if !now.Before(v.expires) {
			delete(t.codes, k)
		}
	}
	if len(t.codes) >= 1000 {
		return "" // bounded; legitimate use is a handful at a time
	}
	t.codes[hashToken(code)] = c
	return code
}

// take removes and returns a live code.
func (t *linkTable) take(code string, now time.Time) (linkCode, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	h := hashToken(code)
	c, ok := t.codes[h]
	delete(t.codes, h)
	return c, ok && now.Before(c.expires)
}

// portOf is ":port" when r came to a port other than 443: every hostname
// is served by the same listener, so they share it.
func portOf(r *http.Request) string {
	if _, port, err := net.SplitHostPort(r.Host); err == nil && port != "" && port != "443" {
		return ":" + port
	}
	return ""
}

// appAllows checks that dev may use app (nil: Jellyfin) on this host, or
// writes the refusal.
func (g *Gate) appAllows(w http.ResponseWriter, r *http.Request, dev *Device, app *appRoute) bool {
	if dev.LinkedHost != "" && dev.LinkedHost != requestHost(r) {
		// A key linked for one application is no use anywhere else.
		g.unauthenticated(w, r, "")
		return false
	}
	if g.allowsApp(app, dev.SubjectID) {
		return true
	}
	if r.Method == http.MethodGet && acceptsHTML(r) {
		http.Redirect(w, r, pathPrefix+"?reason=app_not_allowed&next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return false
	}
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "access_denied", "reason": "app_not_allowed"})
	return false
}

// linkedTo lists the devices linked to parentID.
func (g *Gate) linkedTo(parentID string) []string {
	var out []string
	g.store.View(func(d *storeData) {
		for id, dev := range d.Devices {
			if dev.ParentID == parentID {
				out = append(out, id)
			}
		}
	})
	return out
}

// endAccess drops what lets a device and the devices linked to it in, in
// the order accessChanged requires.
func (g *Gate) endAccess(id string) {
	ids := append([]string{id}, g.linkedTo(id)...)
	for _, d := range ids {
		g.sessions.removeDevice(d)
		g.grants.removeDevice(d)
	}
	g.accessChanged()
	for _, d := range ids {
		g.streams.cancelDevice(d)
		g.verifications.removeDevice(d)
	}
}

// ---- endpoints ----

// handleSite tells a page which host browsers sign in on, and whether this
// host is an application's.
func (g *Gate) handleSite(w http.ResponseWriter, r *http.Request) {
	rt := g.routing.Load()
	out := map[string]any{"app": false}
	if app := rt.apps[requestHost(r)]; app != nil {
		out["app"], out["app_name"] = true, app.Name
		if rt.primaryHost != "" {
			out["sign_in_origin"] = "https://" + rt.primaryHost + portOf(r)
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

// handleLinkCode issues a link code for an application host to the browser
// signed in here (its session cookie).
func (g *Gate) handleLinkCode(w http.ResponseWriter, r *http.Request) {
	if !g.stepRequest(w, r) {
		return
	}
	var req struct {
		Host string `json:"host"`
	}
	if err := g.readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	rt := g.routing.Load()
	if host := requestHost(r); rt.apps[host] != nil {
		writeError(w, http.StatusBadRequest, "ask the sign-in host for link codes")
		return
	}
	app := rt.apps[req.Host]
	if app == nil {
		writeError(w, http.StatusNotFound, "no application has that hostname")
		return
	}
	auth := g.authorizeRequest(w, r)
	if auth == nil {
		return
	}
	dev := auth.dev
	if dev.ParentID != "" {
		writeError(w, http.StatusBadRequest, "a linked device can't link others")
		return
	}
	if !g.allowsApp(app, dev.SubjectID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "access_denied", "reason": "app_not_allowed"})
		return
	}
	now := g.cfg.Now()
	code := g.links.put(linkCode{parentID: dev.ID, host: req.Host, ip: clientIP(r), expires: now.Add(linkCodeTTL)}, now)
	if code == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable"})
		return
	}
	g.audit.write(now, "link_code_issued", map[string]any{"device_id": dev.ID, "host": req.Host, "ip": clientIP(r)})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"code": code, "origin": "https://" + req.Host + portOf(r),
		"expires_in_seconds": int(linkCodeTTL.Seconds())})
}

// handleLinkRedeem records the key a browser made on an application host as
// a device linked to the one that asked for the code.
func (g *Gate) handleLinkRedeem(w http.ResponseWriter, r *http.Request) {
	if !g.stepRequest(w, r) {
		return
	}
	var req struct {
		Code      string `json:"code"`
		PublicKey string `json:"public_key"`
		Proof     string `json:"proof"`
	}
	if err := g.readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	now := g.cfg.Now()
	ip, host := clientIP(r), requestHost(r)
	fields := map[string]any{"host": host}
	c, ok := g.links.take(req.Code, now)
	if !ok || c.host != host {
		g.fail(w, r, http.StatusUnauthorized, "link_failed", "link code invalid, used or expired", fields)
		return
	}
	fields["parent_id"] = c.parentID
	if c.ip != ip {
		g.fail(w, r, http.StatusUnauthorized, "link_failed", "link code used from another address", fields)
		return
	}
	app := g.routing.Load().apps[host]
	parent := g.activeDevice(c.parentID)
	if app == nil || parent == nil || !g.allowsApp(app, parent.SubjectID) {
		g.fail(w, r, http.StatusForbidden, "link_failed", "this application or device is no longer available", fields)
		return
	}
	spki, err := decodeB64(req.PublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "public_key is not base64")
		return
	}
	pub, err := parseP256PublicKey(spki)
	if err != nil {
		writeError(w, http.StatusBadRequest, "public_key must be an ECDSA P-256 SubjectPublicKeyInfo")
		return
	}
	proof, err := decodeB64(req.Proof)
	if err != nil || !verifyP256(pub, linkMessage(req.Code), proof) {
		g.fail(w, r, http.StatusUnauthorized, "link_failed", "proof signature invalid", fields)
		return
	}
	dev := Device{ID: newID("dev_"), Name: cleanName(parent.Name + " · " + app.Name), Platform: "web", Kind: KindECDSA,
		PublicKey: spki, CreatedAt: now, EnrolledFrom: ip, SubjectID: parent.SubjectID, ProfileID: parent.ProfileID,
		ParentID: parent.ID, LinkedHost: host}
	// The parent just signed in from this address under its policy; the
	// linked key starts approved there too.
	pol := g.policyFor(&dev)
	if pol.Policy.IP.Enabled {
		dev.Networks = []NetworkApproval{{ID: newID("net_"), Network: networkKey(ip, pol.Policy.IP), Method: "linked",
			ApprovedAt: now, ExpiresAt: now.Add(pol.approvalTTL()), PolicyVersion: pol.Version}}
	}
	errGone := errors.New("parent gone")
	err = g.store.Update(func(d *storeData) error {
		p := d.Devices[parent.ID]
		if !p.Active() || p.Suspended != "" {
			return errGone
		}
		for _, other := range d.Devices {
			if string(other.PublicKey) == string(spki) {
				return errKeyDup
			}
		}
		stored := dev
		d.Devices[dev.ID] = &stored
		return nil
	})
	switch {
	case errors.Is(err, errGone):
		g.fail(w, r, http.StatusForbidden, "link_failed", "the device that asked for this link is no longer active", fields)
		return
	case errors.Is(err, errKeyDup):
		writeError(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		writeError(w, http.StatusServiceUnavailable, "could not save")
		return
	}
	g.audit.write(now, "device_linked", map[string]any{"device_id": dev.ID, "parent_id": parent.ID, "host": host,
		"app": app.Name, "ip": ip})
	g.alerts.send(fmt.Sprintf("🔗 %q was linked to %s (%s)", parent.Name, app.Name, host))
	writeJSON(w, http.StatusCreated, map[string]any{"device": enrollResponse{DeviceID: dev.ID, Kind: dev.Kind}})
}
