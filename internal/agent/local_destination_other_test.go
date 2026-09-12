//go:build !darwin || !cgo

package agent_test

// No native local-peer attestation is provided on other build targets.
const wantTrustedLocalDestination = false
