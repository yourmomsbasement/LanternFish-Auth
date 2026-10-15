package gate

import (
	"errors"
	"fmt"
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
	SchemaVersion int            `json:"schema_version"`
	Session       SessionPolicy  `json:"session"`
	IP            IPPolicy       `json:"ip"`
	Schedule      SchedulePolicy `json:"schedule"`
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
	streamContinuity = "continuity"
	streamStrict     = "strict"
	onChangeDeny     = "deny"
	onChangeKeyProof = "key_proof"
	onChangeVerify   = "additional_verification"
)

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
	}
}

var weekdays = map[string]time.Weekday{
	"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday,
	"thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday,
}

// Validate checks the whole policy, returning every problem found.
func (p *Policy) Validate() error {
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
	case onChangeDeny, onChangeKeyProof:
	case onChangeVerify:
		bad(`ip.on_change "additional_verification" needs TOTP or WebAuthn, which aren't available yet; use "deny" or "key_proof"`)
	default:
		bad(`ip.on_change must be "deny" or "key_proof"`)
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
	Version  int
	Scope    string
	Policy   Policy
	schedule *compiledSchedule
}

func compilePolicy(version int, scope string, p Policy) (*compiledPolicy, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	cs, err := compileSchedule(p.Schedule)
	if err != nil {
		return nil, err
	}
	return &compiledPolicy{Version: version, Scope: scope, Policy: p, schedule: cs}, nil
}

func (c *compiledPolicy) sessionTTL() time.Duration {
	return time.Duration(c.Policy.Session.TTLSeconds) * time.Second
}

func (c *compiledPolicy) approvalTTL() time.Duration {
	return time.Duration(c.Policy.IP.ApprovalTTLSeconds) * time.Second
}
