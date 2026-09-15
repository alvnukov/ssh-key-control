package confirmation

import "time"

// Decision describes the gate's answer, not a completed signature or login.
// It deliberately excludes comments, prompts and signed request contents.
type Decision struct {
	KeyFingerprint, HostFingerprint, User string
	Outcome, Source, Scope                string
	ExpiresAt                             *time.Time
	// Process names the program a timed decision was tied to, and PID with
	// Version says which run of it. They are empty for a decision that was
	// not anchored, which is every refusal and every one-off answer.
	Process        string
	ProcessPID     int32
	ProcessVersion uint32
}
