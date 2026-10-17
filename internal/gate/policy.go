package gate

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Policy is an access policy (schema version 2), applied globally or through
// a named profile assigned to devices. See docs/PROTOCOL.md, "Access policy".
//
// SECURITY: a policy is validated as a whole before it can be published, so
// a typo can't silently weaken or accidentally block access. A deliberate
// block is expressed explicitly (a schedule window or blackout), never by an
// invalid configuration.
type Policy struct {
	SchemaVersion int                `json:"schema_version"`
	Session       SessionPolicy      `json:"session"`
	IP            IPPolicy           `json:"ip"`
	Schedule      SchedulePolicy     `json:"schedule"`
	Verification  VerificationPolicy `json:"verification"`
	TOTP          TOTPPolicy         `json:"totp"`
	WebAuthn      WebAuthnPolicy     `json:"webauthn"`
	Geo           GeoPolicy          `json:"geo"`
	MAC           MACPolicy          `json:"mac"`
}

// VerificationPolicy says which factors additional verification needs.
// Every listed factor is required (WebAuthn AND authenticator code, never
// one standing in for the other).
type VerificationPolicy struct {
	// ReauthenticateAfterSeconds bounds factor authentication age, independent of key/session renewal. Zero disables it.
	ReauthenticateAfterSeconds int      `json:"reauthenticate_after_seconds"`
	ReauthenticateRequiredAll  []string `json:"reauthenticate_required_all"`
	// NewNetworkRequiredAll: factors for a device on a network it isn't
	// approved for (ip.on_change "additional_verification"), and for the geo
	// and MAC rules whose action is "additional_verification".
	NewNetworkRequiredAll []string `json:"new_network_required_all"`
	// EnrollmentRequiredAll: factors the owner must verify with before a new
	// device is activated.
	EnrollmentRequiredAll []string `json:"enrollment_required_all"`
	PendingTTLSeconds     int      `json:"pending_ttl_seconds"`
	MaxFailedCodeAttempts int      `json:"max_failed_code_attempts"`
}

// TOTPPolicy enables authenticator-app codes (RFC 6238: 6 digits, 30 s,
// HMAC-SHA-1, for compatibility with common apps).
type TOTPPolicy struct {
	Enabled bool `json:"enabled"`
	// AllowedStepDrift accepts codes this many 30-second steps early or late (0 or 1).
	AllowedStepDrift int `json:"allowed_step_drift"`
	// RecoveryCodes lets an owner who lost their authenticator set up a new
	// one with a one-time recovery code (alerted and audited).
	RecoveryCodes bool `json:"recovery_codes"`
}

// WebAuthnPolicy enables passkeys and security keys. The relying party ID
// and origins are deployment settings (LANTERNFISH_WEBAUTHN_RP_ID,
// LANTERNFISH_WEBAUTHN_ORIGINS), never policy.
type WebAuthnPolicy struct {
	Enabled bool `json:"enabled"`
	// Attestation: "none" (don't ask), "collect_if_available" (record what
	// the authenticator offers), or "require_trusted" (only authenticators
	// the FIDO metadata service vouches for).
	Attestation string `json:"attestation"`
	// UserVerification: "required" (PIN or biometric) or "preferred".
	UserVerification    string `json:"user_verification"`
	AllowBackupEligible bool   `json:"allow_backup_eligible"`
}

// GeoPolicy applies country rules using a local GeoIP database.
type GeoPolicy struct {
	Mode             string   `json:"mode"` // "off", "observe" or "enforce"
	CountryAllowlist []string `json:"country_allowlist"`
	CountryDenylist  []string `json:"country_denylist"`
	// UnknownAction: what an unknown, private or stale location does under
	// "enforce": "deny", "additional_verification" or "observe".
	UnknownAction string `json:"unknown_action"`
	// NewCountryAction: a country the device hasn't been approved in.
	NewCountryAction string `json:"new_country_action"`
	// ExemptNetworks (CIDRs) skip country rules entirely: addresses there
	// have no country (your home LAN, a VPN you run). Shown in the
	// dashboard; never implied.
	ExemptNetworks []string `json:"exempt_networks"`
}

// MACPolicy handles interface addresses reported by native clients. A MAC
// is an administrative signal, not proof of a device: browsers can't report
// one, and a modified client can report anything.
type MACPolicy struct {
	Collect bool `json:"collect"`
	// RequireReport denies sessions without a fresh signed report. Only
	// allowed on a profile, for native devices.
	RequireReport            bool   `json:"require_report"`
	OnChange                 string `json:"on_change"` // "observe", "additional_verification" or "reenroll"
	MaxObservationAgeSeconds int    `json:"max_observation_age_seconds"`
}

type SessionPolicy struct {
	// TTLSeconds is a session's hard maximum lifetime.
	TTLSeconds int `json:"ttl_seconds"`
	// MaxPerDevice bounds live sessions per device; a new one replaces the oldest.
	MaxPerDevice int `json:"max_per_device"`
	// StreamExpiryMode: "continuity" lets a connection that is already open
	// (a playing stream, a WebSocket) outlive its session; every new request
	// still needs a valid one. "strict" closes connections when their session
	// expires. Either way, revocation, a schedule end or a policy block closes
	// them at once.
	StreamExpiryMode string `json:"stream_expiry_mode"`
}

type IPPolicy struct {
	Enabled bool `json:"enabled"`
	// Match "exact" binds to the full address; "prefix" to the network given
	// by IPv4PrefixLen / IPv6PrefixLen.
	Match         string `json:"match"`
	IPv4PrefixLen int    `json:"ipv4_prefix_len,omitempty"`
	IPv6PrefixLen int    `json:"ipv6_prefix_len,omitempty"`
	// OnChange decides what a valid device key proves from a network the
	// device isn't approved on: "deny", or "key_proof" (approve the new
	// network on a fresh proof of the device key). "additional_verification"
	// is reserved for TOTP/WebAuthn and rejected until those exist.
	OnChange           string `json:"on_change"`
	ApprovalTTLSeconds int    `json:"approval_ttl_seconds"`
	RememberedNetworks int    `json:"remembered_networks"`
}

type SchedulePolicy struct {
	Enabled  bool   `json:"enabled"`
	Timezone string `json:"timezone"`
	// WeeklyWindows are the times access is allowed, in Timezone.
	WeeklyWindows []WeeklyWindow `json:"weekly_windows"`
	// ValidFrom / ValidUntil bound access to a date range: [from, until).
	ValidFrom  *time.Time `json:"valid_from"`
	ValidUntil *time.Time `json:"valid_until"`
	// Blackouts deny access in [start, end), overriding the windows.
	Blackouts []Interval `json:"blackout_intervals"`
}

// WeeklyWindow allows access on Days from Start to End, local time, as the
// half-open interval [Start, End). An End at or before Start runs past
// midnight into the next day; End "24:00" means midnight at the day's end.
type WeeklyWindow struct {
	Days  []string `json:"days"`
	Start string   `json:"start"`
	End   string   `json:"end"`
}

type Interval struct {
	Start  time.Time `json:"start"`
	End    time.Time `json:"end"`
	Reason string    `json:"reason,omitempty"`
}

const policySchemaVersion = 2

const (
	factorTOTP     = "totp"
	factorWebAuthn = "webauthn"

	geoOff     = "off"
	geoObserve = "observe"
	geoEnforce = "enforce"

	actDeny    = "deny"
	actVerify  = "additional_verification"
	actObserve = "observe"
	actReenrol = "reenroll"

	attNone     = "none"
	attCollect  = "collect_if_available"
	attRequired = "require_trusted"
)

const (
	streamContinuity = "continuity"
	streamStrict     = "strict"
	onChangeDeny     = "deny"
	onChangeKeyProof = "key_proof"
	onChangeVerify   = "additional_verification"
)

// normalize fills in defaults for settings a stored policy predates or
// leaves empty, so older policies keep their meaning.
func (p *Policy) normalize() {
	v := &p.Verification
	if v.PendingTTLSeconds == 0 {
		v.PendingTTLSeconds = 300
	}
	if v.MaxFailedCodeAttempts == 0 {
		v.MaxFailedCodeAttempts = 5
	}
	if v.ReauthenticateRequiredAll == nil {
		v.ReauthenticateRequiredAll = []string{}
	}
	if v.NewNetworkRequiredAll == nil {
		v.NewNetworkRequiredAll = []string{}
	}
	if v.EnrollmentRequiredAll == nil {
		v.EnrollmentRequiredAll = []string{}
	}
	if p.WebAuthn.Attestation == "" {
		p.WebAuthn.Attestation = attCollect
	}
	if p.WebAuthn.UserVerification == "" {
		p.WebAuthn.UserVerification = "required"
	}
	g := &p.Geo
	if g.Mode == "" {
		g.Mode = geoOff
	}
	if g.UnknownAction == "" {
		g.UnknownAction = actDeny
	}
	if g.NewCountryAction == "" {
		g.NewCountryAction = actVerify
	}
	if g.CountryAllowlist == nil {
		g.CountryAllowlist = []string{}
	}
	if g.CountryDenylist == nil {
		g.CountryDenylist = []string{}
	}
	if g.ExemptNetworks == nil {
		g.ExemptNetworks = []string{}
	}
	for i, c := range g.CountryAllowlist {
		g.CountryAllowlist[i] = strings.ToUpper(strings.TrimSpace(c))
	}
	for i, c := range g.CountryDenylist {
		g.CountryDenylist[i] = strings.ToUpper(strings.TrimSpace(c))
	}
	if p.MAC.OnChange == "" {
		p.MAC.OnChange = actVerify
	}
	if p.MAC.MaxObservationAgeSeconds == 0 {
		p.MAC.MaxObservationAgeSeconds = 600
	}
}

// LegacyPolicy reproduces the behaviour before access policies existed:
// sessions of ttl, no network binding, no schedule. Existing installations
// start on it, so upgrading changes nothing until an administrator publishes
// a policy.
func LegacyPolicy(ttl time.Duration) Policy {
	return Policy{
		SchemaVersion: policySchemaVersion,
		Session: SessionPolicy{
			TTLSeconds:       int(ttl / time.Second),
			MaxPerDevice:     maxSessionsPerDevice,
			StreamExpiryMode: streamContinuity,
		},
		IP: IPPolicy{Enabled: false, Match: "exact", OnChange: onChangeKeyProof,
			ApprovalTTLSeconds: 86400, RememberedNetworks: 1},
		Schedule: SchedulePolicy{Enabled: false, Timezone: "UTC"},
		TOTP:     TOTPPolicy{AllowedStepDrift: 1, RecoveryCodes: true},
		WebAuthn: WebAuthnPolicy{AllowBackupEligible: true},
	}
}

// RecommendedPolicy is the suggested starting point for browsers and TV
// apps: five-minute sessions; the exact IPv4 address or the IPv6 /64 (IPv6
// addresses rotate within a /64); a new network approved on a fresh key
// proof for now (TOTP/WebAuthn approval arrives with those factors); no
// schedule until one is configured.
func RecommendedPolicy() Policy {
	return Policy{
		SchemaVersion: policySchemaVersion,
		Session:       SessionPolicy{TTLSeconds: 300, MaxPerDevice: maxSessionsPerDevice, StreamExpiryMode: streamContinuity},
		IP: IPPolicy{Enabled: true, Match: "prefix", IPv4PrefixLen: 32, IPv6PrefixLen: 64,
			OnChange: onChangeKeyProof, ApprovalTTLSeconds: 86400, RememberedNetworks: 1},
		Schedule: SchedulePolicy{Enabled: false, Timezone: "America/Chicago"},
		// Factors are proposals: turn them on once the owners have set up an
		// authenticator, then switch ip.on_change to additional_verification.
		TOTP:     TOTPPolicy{AllowedStepDrift: 1, RecoveryCodes: true},
		WebAuthn: WebAuthnPolicy{Attestation: attCollect, UserVerification: "required", AllowBackupEligible: true},
		// Geo stays off here; the Gate proposes "observe" when it has a
		// country database (see handleRecommendedPolicy).
	}
}

var weekdays = map[string]time.Weekday{
	"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday,
	"thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday,
}

// Validate checks the whole policy, returning every problem found.
// It fills in defaults first (see normalize).
func (p *Policy) Validate() error {
	p.normalize()
	var errs []string
	bad := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }

	if p.SchemaVersion != policySchemaVersion {
		bad("schema_version must be %d", policySchemaVersion)
	}
	s := p.Session
	if s.TTLSeconds < 60 || s.TTLSeconds > 86400 {
		bad("session.ttl_seconds must be between 60 and 86400")
	}
	if s.MaxPerDevice < 1 || s.MaxPerDevice > 64 {
		bad("session.max_per_device must be between 1 and 64")
	}
	if s.StreamExpiryMode != streamContinuity && s.StreamExpiryMode != streamStrict {
		bad(`session.stream_expiry_mode must be "continuity" or "strict"`)
	}

	ip := p.IP
	switch ip.Match {
	case "exact":
	case "prefix":
		if ip.IPv4PrefixLen < 8 || ip.IPv4PrefixLen > 32 {
			bad("ip.ipv4_prefix_len must be between 8 and 32")
		}
		if ip.IPv6PrefixLen < 32 || ip.IPv6PrefixLen > 128 {
			bad("ip.ipv6_prefix_len must be between 32 and 128")
		}
	default:
		bad(`ip.match must be "exact" or "prefix"`)
	}
	switch ip.OnChange {
	case onChangeDeny, onChangeKeyProof, onChangeVerify:
	default:
		bad(`ip.on_change must be "deny", "key_proof" or "additional_verification"`)
	}
	if ip.ApprovalTTLSeconds < 3600 || ip.ApprovalTTLSeconds > 30*86400 {
		bad("ip.approval_ttl_seconds must be between 3600 (1 hour) and 2592000 (30 days)")
	}
	if ip.RememberedNetworks < 1 || ip.RememberedNetworks > 10 {
		bad("ip.remembered_networks must be between 1 and 10")
	}

	sc := p.Schedule
	if _, err := time.LoadLocation(sc.Timezone); err != nil || sc.Timezone == "" || strings.EqualFold(sc.Timezone, "Local") {
		bad("schedule.timezone %q is not an IANA time zone", sc.Timezone)
	}
	if sc.Enabled && len(sc.WeeklyWindows) == 0 {
		bad("schedule.enabled with no weekly_windows would block all access; add windows, or use a blackout for a deliberate block")
	}
	for i, w := range sc.WeeklyWindows {
		if len(w.Days) == 0 {
			bad("schedule.weekly_windows[%d].days is empty", i)
		}
		for _, d := range w.Days {
			if _, ok := weekdays[strings.ToLower(d)]; !ok {
				bad("schedule.weekly_windows[%d]: unknown day %q (use sun, mon, tue, wed, thu, fri, sat)", i, d)
			}
		}
		start, err1 := parseClock(w.Start, false)
		end, err2 := parseClock(w.End, true)
		if err1 != nil {
			bad("schedule.weekly_windows[%d].start: %v", i, err1)
		}
		if err2 != nil {
			bad("schedule.weekly_windows[%d].end: %v", i, err2)
		}
		if err1 == nil && err2 == nil && start == end {
			bad("schedule.weekly_windows[%d]: start and end are equal; use 00:00-24:00 for a whole day", i)
		}
	}
	if sc.ValidFrom != nil && sc.ValidUntil != nil && !sc.ValidFrom.Before(*sc.ValidUntil) {
		bad("schedule.valid_from must be before schedule.valid_until")
	}
	for i, b := range sc.Blackouts {
		if !b.Start.Before(b.End) {
			bad("schedule.blackout_intervals[%d]: start must be before end", i)
		}
	}
	if len(sc.WeeklyWindows) > 64 || len(sc.Blackouts) > 256 {
		bad("schedule has too many entries (at most 64 windows and 256 blackouts)")
	}

	// Factors and additional verification.
	enabled := map[string]bool{factorTOTP: p.TOTP.Enabled, factorWebAuthn: p.WebAuthn.Enabled}
	checkFactors := func(field string, list []string) {
		seen := map[string]bool{}
		for _, f := range list {
			if f != factorTOTP && f != factorWebAuthn {
				bad("%s: unknown factor %q (use \"totp\" or \"webauthn\")", field, f)
				continue
			}
			if seen[f] {
				bad("%s lists %q twice", field, f)
			}
			seen[f] = true
			if !enabled[f] {
				bad("%s requires %q, which this policy doesn't enable", field, f)
			}
		}
	}
	vp := p.Verification
	checkFactors("verification.new_network_required_all", vp.NewNetworkRequiredAll)
	checkFactors("verification.enrollment_required_all", vp.EnrollmentRequiredAll)
	checkFactors("verification.reauthenticate_required_all", vp.ReauthenticateRequiredAll)
	if vp.ReauthenticateAfterSeconds < 0 || vp.ReauthenticateAfterSeconds > 31536000 {
		bad("verification.reauthenticate_after_seconds must be between 0 and 31536000")
	}
	if vp.ReauthenticateAfterSeconds > 0 && len(vp.ReauthenticateRequiredAll) == 0 {
		bad("periodic reauthentication requires at least one factor")
	}
	if vp.PendingTTLSeconds < 60 || vp.PendingTTLSeconds > 900 {
		bad("verification.pending_ttl_seconds must be between 60 and 900")
	}
	if vp.MaxFailedCodeAttempts < 1 || vp.MaxFailedCodeAttempts > 10 {
		bad("verification.max_failed_code_attempts must be between 1 and 10")
	}
	needsStepUp := ip.OnChange == onChangeVerify ||
		(p.Geo.Mode == geoEnforce && (p.Geo.UnknownAction == actVerify || p.Geo.NewCountryAction == actVerify)) ||
		((p.MAC.Collect || p.MAC.RequireReport) && p.MAC.OnChange == actVerify)
	if needsStepUp && len(vp.NewNetworkRequiredAll) == 0 {
		bad("additional verification is configured, but verification.new_network_required_all lists no factors")
	}
	if p.TOTP.AllowedStepDrift < 0 || p.TOTP.AllowedStepDrift > 1 {
		bad("totp.allowed_step_drift must be 0 or 1")
	}
	switch p.WebAuthn.Attestation {
	case attNone, attCollect, attRequired:
	default:
		bad(`webauthn.attestation must be "none", "collect_if_available" or "require_trusted"`)
	}
	switch p.WebAuthn.UserVerification {
	case "required", "preferred":
	default:
		bad(`webauthn.user_verification must be "required" or "preferred"`)
	}

	g := p.Geo
	switch g.Mode {
	case geoOff, geoObserve, geoEnforce:
	default:
		bad(`geo.mode must be "off", "observe" or "enforce"`)
	}
	for _, list := range [][]string{g.CountryAllowlist, g.CountryDenylist} {
		for _, c := range list {
			if len(c) != 2 || c[0] < 'A' || c[0] > 'Z' || c[1] < 'A' || c[1] > 'Z' {
				bad("geo: %q is not a two-letter country code (ISO 3166-1, e.g. US)", c)
			}
		}
	}
	for _, n := range g.ExemptNetworks {
		if _, err := netip.ParsePrefix(n); err != nil {
			bad("geo.exempt_networks: %q is not a CIDR like 192.168.0.0/16", n)
		}
	}
	if len(g.ExemptNetworks) > 64 {
		bad("geo.exempt_networks: at most 64 networks")
	}
	if len(g.CountryAllowlist) > 250 || len(g.CountryDenylist) > 250 {
		bad("geo: too many countries listed")
	}
	if g.Mode == geoEnforce && len(g.CountryAllowlist) == 0 && len(g.CountryDenylist) == 0 {
		bad("geo.mode \"enforce\" needs a country_allowlist or country_denylist")
	}
	switch g.UnknownAction {
	case actDeny, actVerify, actObserve:
	default:
		bad(`geo.unknown_action must be "deny", "additional_verification" or "observe"`)
	}
	switch g.NewCountryAction {
	case actDeny, actVerify, actObserve:
	default:
		bad(`geo.new_country_action must be "deny", "additional_verification" or "observe"`)
	}

	m := p.MAC
	switch m.OnChange {
	case actObserve, actVerify, actReenrol:
	default:
		bad(`mac.on_change must be "observe", "additional_verification" or "reenroll"`)
	}
	if m.RequireReport && !m.Collect {
		bad("mac.require_report needs mac.collect")
	}
	if m.MaxObservationAgeSeconds < 60 || m.MaxObservationAgeSeconds > 86400 {
		bad("mac.max_observation_age_seconds must be between 60 and 86400")
	}

	if len(errs) > 0 {
		return &PolicyError{Problems: errs}
	}
	return nil
}

// PolicyError lists everything wrong with a policy.
type PolicyError struct{ Problems []string }

func (e *PolicyError) Error() string { return "invalid policy: " + strings.Join(e.Problems, "; ") }

// parseClock parses "HH:MM" into minutes after midnight. "24:00" is allowed
// only as an end.
func parseClock(s string, isEnd bool) (int, error) {
	digit := func(c byte) bool { return c >= '0' && c <= '9' }
	if len(s) != 5 || s[2] != ':' || !digit(s[0]) || !digit(s[1]) || !digit(s[3]) || !digit(s[4]) {
		return 0, errors.New(`time must look like "HH:MM"`)
	}
	h := int(s[0]-'0')*10 + int(s[1]-'0')
	m := int(s[3]-'0')*10 + int(s[4]-'0')
	if isEnd && h == 24 && m == 0 {
		return 24 * 60, nil
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, fmt.Errorf("%q is not a valid time of day", s)
	}
	return h*60 + m, nil
}

// compiledPolicy is a validated policy ready for request-time evaluation.
type compiledPolicy struct {
	Version   int
	Scope     string
	Policy    Policy
	schedule  *compiledSchedule
	geoExempt []netip.Prefix
}

// geoExempted reports whether ip is in the policy's geo-exempt networks.
func (c *compiledPolicy) geoExempted(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range c.geoExempt {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func compilePolicy(version int, scope string, p Policy) (*compiledPolicy, error) {
	p.normalize()
	if err := p.Validate(); err != nil {
		return nil, err
	}
	cs, err := compileSchedule(p.Schedule)
	if err != nil {
		return nil, err
	}
	cp := &compiledPolicy{Version: version, Scope: scope, Policy: p, schedule: cs}
	for _, n := range p.Geo.ExemptNetworks {
		pfx, _ := netip.ParsePrefix(n)
		cp.geoExempt = append(cp.geoExempt, pfx.Masked())
	}
	return cp, nil
}

func (c *compiledPolicy) sessionTTL() time.Duration {
	return time.Duration(c.Policy.Session.TTLSeconds) * time.Second
}

func (c *compiledPolicy) approvalTTL() time.Duration {
	return time.Duration(c.Policy.IP.ApprovalTTLSeconds) * time.Second
}
