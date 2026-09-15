package ui

import "context"

// TemporaryDecision is a live snapshot, not an authorization capability.
type TemporaryDecision struct {
	ID              string `json:"id"`
	KeyFingerprint  string `json:"keyFingerprint"`
	HostFingerprint string `json:"hostFingerprint"`
	Host            string `json:"host"`
	User            string `json:"user"`
	Allowed         bool   `json:"allowed"`
	ExpiresAt       string `json:"expiresAt"`
	// Process names the program this decision is anchored to and says whether
	// it is still running. An empty name means the decision applies to every
	// program, which is how refusals and unanchored approvals are stored.
	Process     string `json:"process,omitempty"`
	ProcessPID  int32  `json:"processPid,omitempty"`
	ProcessLive bool   `json:"processLive,omitempty"`
}

// DecisionChange can only edit/revoke an existing opaque ID. It cannot create
// a grant, change its destination, or turn a refusal into an approval.
// Revoking by process still names one row: the agent, not the window, decides
// which other rows belong to the same program.
type DecisionChange struct {
	Action   string `json:"action"`
	ID       string `json:"id,omitempty"`
	Minutes  int    `json:"minutes,omitempty"`
	EndOfDay bool   `json:"endOfDay,omitempty"`
}

type DecisionManager interface {
	ManageDecisions(context.Context, []TemporaryDecision, string, bool) (DecisionChange, error)
}
