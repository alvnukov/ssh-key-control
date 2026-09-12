package cli

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/alvnukov/ssh-key-control/internal/history"
	"github.com/alvnukov/ssh-key-control/internal/launchd"
	"github.com/alvnukov/ssh-key-control/internal/nativemonitor"
)

// nativeAgentMonitor changes only its own monitoring preference; it never changes
// Apple's launchd policy, Keychain, or private key files.
func (a *App) nativeAgentMonitor(args []string) error {
	if len(args) != 1 {
		return &usageError{"native-agent-monitor needs status, enable or disable"}
	}
	switch args[0] {
	case "enable", "disable":
		if err := nativemonitor.SavePolicy(a.HistoryDir, nativemonitor.Policy{Enabled: args[0] == "enable"}); err != nil {
			return err
		}
	case "status":
	default:
		return &usageError{"native-agent-monitor needs status, enable or disable"}
	}
	policy, err := nativemonitor.ReadPolicy(a.HistoryDir)
	if err != nil {
		return err
	}
	return json.NewEncoder(a.Stdout).Encode(policy)
}

type nativeConnector struct {
	client         launchd.Client
	protected      []string
	path           string
	nextDiscovery  time.Time
	discoveryError error
}

func (c *nativeConnector) connect(ctx context.Context) (net.Conn, error) {
	if time.Now().After(c.nextDiscovery) {
		c.nextDiscovery = time.Now().Add(30 * time.Second)
		path, err := c.client.NativeSocket(ctx)
		c.path = path
		if errors.Is(err, launchd.ErrNotLoaded) {
			err = nativemonitor.ErrUnavailable
		}
		c.discoveryError = err
		if err != nil {
			c.nextDiscovery = time.Now().Add(5 * time.Second)
			return nil, err
		}
	}
	if c.discoveryError != nil {
		return nil, c.discoveryError
	}
	if c.path == "" {
		return nil, nativemonitor.ErrUnavailable
	}
	info, err := validateNativeEndpoint(c.path, c.protected)
	if err != nil {
		c.path, c.discoveryError = "", err
		c.nextDiscovery = time.Now().Add(5 * time.Second)
		return nil, err
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", c.path)
	if err != nil {
		c.path, c.discoveryError = "", err
		c.nextDiscovery = time.Now().Add(5 * time.Second)
		return nil, err
	}
	after, err := validateNativeEndpoint(c.path, c.protected)
	if err != nil || !os.SameFile(info, after) {
		conn.Close()
		return nil, errors.New("native SSH agent socket changed during connection")
	}
	return conn, nil
}
func validateNativeEndpoint(path string, protected []string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, nativemonitor.ErrUnavailable
	}
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return nil, errors.New("native SSH agent endpoint is not a socket")
	}
	for _, own := range protected {
		if own == "" {
			continue
		}
		if filepath.Clean(path) == filepath.Clean(own) {
			return nil, errors.New("refusing to monitor the protected agent")
		}
		ownInfo, statErr := os.Stat(own)
		if statErr == nil && os.SameFile(info, ownInfo) {
			return nil, errors.New("refusing an alias of the protected agent")
		}
		if statErr != nil && !os.IsNotExist(statErr) {
			return nil, errors.New("cannot exclude protected agent endpoint")
		}
	}
	return info, nil
}
func (a *App) runNativeMonitor(ctx context.Context, protected []string, record func(history.Event)) {
	connector := &nativeConnector{client: a.Launchctl, protected: protected}
	monitor := nativemonitor.Monitor{
		Directory: a.HistoryDir, Connect: connector.connect,
		Record: func(e nativemonitor.Event) {
			record(history.Event{Kind: "native_agent", Outcome: e.Outcome, Source: "native_monitor", KeyFingerprint: e.Fingerprint})
		},
	}
	monitor.Run(ctx)
}
