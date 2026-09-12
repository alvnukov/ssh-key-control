//go:build !darwin || !cgo

package agent

import "net"

// No attestation means no local-only compatibility exception.
func trustedLocalSSH(net.Conn) bool { return false }
