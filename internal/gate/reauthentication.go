package gate

import "time"

func mergeFactors(a, b []string) []string {
	out := append([]string{}, a...)
	for _, f := range b {
		if !contains(out, f) {
			out = append(out, f)
		}
	}
	return out
}
func recordFactorVerification(dev *Device, factors []string, now time.Time) {
	if dev.FactorVerifiedAt == nil {
		dev.FactorVerifiedAt = map[string]time.Time{}
	}
	for _, f := range factors {
		if f == factorTOTP || f == factorWebAuthn {
			dev.FactorVerifiedAt[f] = now
		}
	}
}

// Only successful factor verification updates the clock. Per-factor timestamps
// prevent a recently used factor from making a different required factor fresh.
func (g *Gate) reauthenticationDecision(dev *Device, d decision, now time.Time) decision {
	if d.pol == nil || (d.outcome != outAllow && d.outcome != outVerify && d.outcome != outNetwork) {
		return d
	}
	v := d.pol.Policy.Verification
	if v.ReauthenticateAfterSeconds <= 0 {
		return d
	}
	var due []string
	for _, f := range v.ReauthenticateRequiredAll {
		at := dev.FactorVerifiedAt[f]
		end := at.Add(time.Duration(v.ReauthenticateAfterSeconds) * time.Second)
		if at.IsZero() || at.After(now) || !now.Before(end) {
			due = append(due, f)
		} else {
			d.expires = earliest(d.expires, end)
			d.hardEnd = earliest(d.hardEnd, end)
		}
	}
	if len(due) > 0 {
		// Ask for the complete configured set to give the user one full interval.
		d.required = mergeFactors(d.required, v.ReauthenticateRequiredAll)
		if d.outcome == outAllow {
			d.outcome, d.reason = outVerify, "reauthentication_required"
		}
	}
	return d
}
