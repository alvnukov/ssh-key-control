package cli

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestNativeMonitorMissingSocketDoesNotPostponeRediscoveryForever(t *testing.T) {
	c := nativeConnector{path: filepath.Join(t.TempDir(), "missing"), nextDiscovery: time.Now().Add(time.Minute)}
	if _, err := c.connect(context.Background()); err == nil {
		t.Fatal("missing socket accepted")
	}
	next := c.nextDiscovery
	for range 3 {
		if _, err := c.connect(context.Background()); err == nil {
			t.Fatal("missing socket accepted")
		}
	}
	if c.path != "" || c.discoveryError == nil || !c.nextDiscovery.Equal(next) {
		t.Fatal("failed connection postponed rediscovery")
	}
}
