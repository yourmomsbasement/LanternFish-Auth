package gate

import (
	"sort"
	"strings"
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
	blackouts []Interval
	instants  []time.Time // exact moments where blackouts and the date range start or end
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
	cs := &compiledSchedule{loc: loc, from: sp.ValidFrom, until: sp.ValidUntil, blackouts: sp.Blackouts}
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
	return cs, nil
}

// allowed reports whether access is allowed at t.
func (cs *compiledSchedule) allowed(t time.Time) bool {
	if cs == nil {
		return true
	}
	for _, b := range cs.blackouts {
		if !t.Before(b.Start) && t.Before(b.End) {
			return false
		}
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
