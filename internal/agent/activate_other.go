//go:build !darwin || !cgo

package agent

import (
	"fmt"
	"net"
)

func ActivateSocket(name string) (net.Listener, error) {
	return nil, fmt.Errorf("launchd socket %q requires a macOS build with cgo enabled", name)
}
