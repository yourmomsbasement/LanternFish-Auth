package gate

import (
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// compiledSchedule evaluates a SchedulePolicy. A nil schedule always allows.
//
// Times are judged by the wall clock in the schedule's time zone, which gives
// the documented daylight-saving behaviour for free: a local minute skipped
// when clocks go forward never occurs, so it grants nothing; a local minute
// repeated when they go back occurs twice, and both count if the wall-clock
// time is inside a window. Server time decides; clients' clocks never do.
type compiledSchedule struct {
	loc       *time.Location
	byDay     [7][]span // minutes after local midnight, [start, end)
	from      *time.Time
	until     *time.Time
	blackouts []Interval  // merged: sorted, disjoint
	instants  []time.Time // exact moments where blackouts and the date range start or end
	allWeek   bool        // the weekly windows cover every minute of every day

	next atomic.Pointer[boundaryMemo] // last nextBoundary result
}

// boundaryMemo remembers that from `from` on, allowed() first changes at
// `at` (or never, if !found). That stays true for any later time before at.
type boundaryMemo struct {
	from, at time.Time
	found    bool
}

type span struct{ start, end int }

func compileSchedule(sp SchedulePolicy) (*compiledSchedule, error) {
	if !sp.Enabled {
		return nil, nil
	}
	loc, err := time.LoadLocation(sp.Timezone)
	if err != nil {
		return nil, err
	}
	cs := &compiledSchedule{loc: loc, from: sp.ValidFrom, until: sp.ValidUntil, blackouts: mergeIntervals(sp.Blackouts)}
	for _, w := range sp.WeeklyWindows {
		start, _ := parseClock(w.Start, false)
		end, _ := parseClock(w.End, true)
		for _, d := range w.Days {
			day := weekdays[strings.ToLower(d)]
			if end > start {
				cs.byDay[day] = append(cs.byDay[day], span{start, end})
				continue
			}
			// Runs past midnight: split into this day's tail and the next
			// day's head.
			cs.byDay[day] = append(cs.byDay[day], span{start, 24 * 60})
			if end > 0 {
				next := (day + 1) % 7
				cs.byDay[next] = append(cs.byDay[next], span{0, end})
			}
		}
	}
	for _, b := range sp.Blackouts {
		cs.instants = append(cs.instants, b.Start, b.End)
	}
	if sp.ValidFrom != nil {
		cs.instants = append(cs.instants, *sp.ValidFrom)
	}
	if sp.ValidUntil != nil {
		cs.instants = append(cs.instants, *sp.ValidUntil)
	}
	sort.Slice(cs.instants, func(i, j int) bool { return cs.instants[i].Before(cs.instants[j]) })
	cs.allWeek = true
	for _, spans := range cs.byDay {
		if !coversDay(spans) {
			cs.allWeek = false
		}
	}
	return cs, nil
}

// mergeIntervals sorts intervals and merges overlapping or touching ones, so
// whether a moment is inside any of them is a binary search.
func mergeIntervals(in []Interval) []Interval {
	out := make([]Interval, 0, len(in))
	for _, iv := range in {
		if iv.End.After(iv.Start) {
			out = append(out, iv)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start.Before(out[j].Start) })
	merged := out[:0]
	for _, iv := range out {
		if n := len(merged); n > 0 && !iv.Start.After(merged[n-1].End) {
			if iv.End.After(merged[n-1].End) {
				merged[n-1].End = iv.End
			}
			continue
		}
		merged = append(merged, iv)
	}
	return merged
}

// coversDay reports whether spans together cover [0, 24h).
func coversDay(spans []span) bool {
	sorted := append([]span(nil), spans...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].start < sorted[j].start })
	reached := 0
	for _, s := range sorted {
		if s.start > reached {
			return false
		}
		if s.end > reached {
			reached = s.end
		}
	}
	return reached >= 24*60
}

// allowed reports whether access is allowed at t.
func (cs *compiledSchedule) allowed(t time.Time) bool {
	if cs == nil {
		return true
	}
	// The first merged blackout ending after t is the only one that can
	// contain it.
	if i := sort.Search(len(cs.blackouts), func(i int) bool { return cs.blackouts[i].End.After(t) }); i < len(cs.blackouts) &&
		!t.Before(cs.blackouts[i].Start) {
		return false
	}
	if cs.from != nil && t.Before(*cs.from) {
		return false
	}
	if cs.until != nil && !t.Before(*cs.until) {
		return false
	}
	local := t.In(cs.loc)
	m := local.Hour()*60 + local.Minute()
	for _, s := range cs.byDay[local.Weekday()] {
		if m >= s.start && m < s.end {
			return true
		}
	}
	return false
}

// nextChange returns the first moment after t, within horizon, at which
// allowed() differs from its value at t, and whether there is one.
//
// Windows can only change on whole minutes; blackouts and the date range can
// change at any instant, so those moments are checked as well.
func (cs *compiledSchedule) nextChange(t time.Time, horizon time.Duration) (time.Time, bool) {
	if cs == nil {
		return time.Time{}, false
	}
	now := cs.allowed(t)
	limit := t.Add(horizon)
	i := sort.Search(len(cs.instants), func(i int) bool { return cs.instants[i].After(t) })
	if cs.allWeek {
		// The weekly windows never change anything; only exact instants can.
		for ; i < len(cs.instants) && !cs.instants[i].After(limit); i++ {
			if cs.allowed(cs.instants[i]) != now {
				return cs.instants[i], true
			}
		}
		return time.Time{}, false
	}
	for c := t.Truncate(time.Minute).Add(time.Minute); !c.After(limit); c = c.Add(time.Minute) {
		// Exact instants that fall before this minute come first.
		for ; i < len(cs.instants) && cs.instants[i].Before(c); i++ {
			if cs.allowed(cs.instants[i]) != now {
				return cs.instants[i], true
			}
		}
		if cs.allowed(c) != now {
			return c, true
		}
	}
	return time.Time{}, false
}

// nextBoundary returns the first moment after t at which allowed() changes,
// however far away, and whether there is one. Access decisions use it.
//
// SECURITY: nextChange only looks scheduleHorizon ahead, and "nothing within
// the horizon" used to be read as "no end", so a connection allowed to
// outlive its session (continuity mode) could outlast a date cutoff or a
// blackout further away. Past the horizon the weekly windows can't be what
// changes access (a schedule that covers every minute of the week is handled
// exactly; for any other, a week without a change can only happen around a
// clock change; then the horizon itself is returned, so a connection is
// closed there and has to be authorized again), so the exact instants are
// searched to the end.
func (cs *compiledSchedule) nextBoundary(t time.Time) (time.Time, bool) {
	if cs == nil {
		return time.Time{}, false
	}
	if m := cs.next.Load(); m != nil && !t.Before(m.from) && (!m.found || t.Before(m.at)) {
		return m.at, m.found
	}
	at, found := cs.nextChange(t, scheduleHorizon)
	if !found {
		if cs.allWeek {
			now := cs.allowed(t)
			for i := sort.Search(len(cs.instants), func(i int) bool { return cs.instants[i].After(t) }); i < len(cs.instants); i++ {
				if cs.allowed(cs.instants[i]) != now {
					at, found = cs.instants[i], true
					break
				}
			}
		} else {
			at, found = t.Add(scheduleHorizon), true
		}
	}
	cs.next.Store(&boundaryMemo{from: t, at: at, found: found})
	return at, found
}

// boundaries lists the next few moments the schedule opens or closes, for
// the policy preview.
func (cs *compiledSchedule) boundaries(t time.Time, n int, horizon time.Duration) []map[string]any {
	out := []map[string]any{}
	limit := t.Add(horizon)
	for len(out) < n {
		c, ok := cs.nextChange(t, limit.Sub(t))
		if !ok {
			break
		}
		state := "closes"
		if cs.allowed(c) {
			state = "opens"
		}
		out = append(out, map[string]any{"at": c.UTC(), "local": c.In(cs.loc).Format("Mon 2006-01-02 15:04 MST"), "access": state})
		t = c
	}
	return out
}
