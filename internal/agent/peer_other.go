//go:build !darwin || !cgo

package agent

import (
	"net"

	"github.com/alvnukov/ssh-key-control/internal/proc"
)

// No attestation means no local-only compatibility exception.
func trustedLocalSSH(net.Conn) bool { return false }

// Without the kernel's audit token there is no trustworthy way to say which
// process is on the other end, so every request here is unanchored.
func peerProcessChain(net.Conn) proc.Chain { return proc.Chain{} }
