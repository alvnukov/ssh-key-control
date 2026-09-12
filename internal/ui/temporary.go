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
}

// DecisionChange can only edit/revoke an existing opaque ID. It cannot create
// a grant, change its destination, or turn a refusal into an approval.
type DecisionChange struct {
	Action   string `json:"action"`
	ID       string `json:"id,omitempty"`
	Minutes  int    `json:"minutes,omitempty"`
	EndOfDay bool   `json:"endOfDay,omitempty"`
}

type DecisionManager interface {
	ManageDecisions(context.Context, []TemporaryDecision, string, bool) (DecisionChange, error)
}
