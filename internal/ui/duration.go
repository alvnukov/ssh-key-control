package ui

import (
	"fmt"
	"time"
)

const MaxCustomDurationMinutes = 1440

// Lifetime validates direction and duration together, at both the helper boundary
// and the lease boundary. endOfDay means the next local midnight, not 24 hours.
func (c Confirmation) Lifetime() (duration time.Duration, endOfDay bool, err error) {
	if c.Scope != "" && c.Scope != GrantOnce && c.Allowed == c.Scope.IsDenyDuration() {
		return 0, false, fmt.Errorf("scope %q does not match confirmation decision", c.Scope)
	}
	custom := c.Scope == GrantCustom || c.Scope == DenyCustom
	if custom {
		if c.DurationMinutes < 1 || c.DurationMinutes > MaxCustomDurationMinutes {
			return 0, false, fmt.Errorf("custom duration must be 1..%d minutes", MaxCustomDurationMinutes)
		}
		return time.Duration(c.DurationMinutes) * time.Minute, false, nil
	}
	if c.DurationMinutes != 0 {
		return 0, false, fmt.Errorf("minutes are only valid for a custom duration")
	}
	switch c.Scope {
	case "", GrantOnce:
		return 0, false, nil
	case Grant5Minutes, Deny5Minutes:
		return 5 * time.Minute, false, nil
	case Grant15Minutes, Deny15Minutes:
		return 15 * time.Minute, false, nil
	case GrantDay, DenyDay:
		return 0, true, nil
	case Deny1Hour:
		return time.Hour, false, nil
	default:
		return 0, false, fmt.Errorf("unsupported confirmation duration %q", c.Scope)
	}
}
