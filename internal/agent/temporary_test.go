package agent

import (
	"context"
	"testing"
)

func TestManagementExtensionOnlyOpensLocalWindow(t *testing.T) {
	calls := 0
	p := NewProtectedWithManagement(func(context.Context, SigningRequest) (bool, error) { return false, nil }, func() error { calls++; return nil })
	c := &protectedConnection{owner: p, ctx: context.Background()}
	if _, err := c.Extension(ManageDecisionsExtension, nil); err != nil || calls != 1 {
		t.Fatalf("open=%v calls=%d", err, calls)
	}
	for _, payload := range [][]byte{[]byte("{}"), []byte("{\"action\":\"update\",\"minutes\":1440}"), {0}} {
		if _, err := c.Extension(ManageDecisionsExtension, payload); err == nil {
			t.Fatal("accepted management payload")
		}
	}
	c.tainted = true
	if _, err := c.Extension(ManageDecisionsExtension, nil); err == nil {
		t.Fatal("tainted connection opened management")
	}
	bound, _, _, _ := localFixture(t, func() bool { return true }, func(context.Context, SigningRequest) (bool, error) { return false, nil })
	bound.owner.openManagement = func() error { calls++; return nil }
	if _, err := bound.Extension(ManageDecisionsExtension, nil); err == nil {
		t.Fatal("bound SSH session opened local management")
	}
	if calls != 1 {
		t.Fatal("invalid requests reached management")
	}
}
