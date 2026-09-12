//go:build darwin && cgo

package agent_test

// The macOS system SSH binary supplies both native peer identity and a signed
// session binding. The loopback integration test must preserve its destination.
const wantTrustedLocalDestination = true
