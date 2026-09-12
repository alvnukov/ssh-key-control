package confirmation

import "time"

// Decision describes the gate's answer, not a completed signature or login.
// It deliberately excludes comments, prompts and signed request contents.
type Decision struct {
	KeyFingerprint, HostFingerprint, User string
	Outcome, Source, Scope                string
	ExpiresAt                             *time.Time
}
