package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRunPublishesSocketBeforeExec(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		dir := t.TempDir()
		link, target := filepath.Join(dir, "ssh-key-control.sock"), filepath.Join(dir, "agent.sock")
		if conflict {
			if err := os.WriteFile(link, []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		rec := &recorder{}
		executed := false
		rt := runtimeWith(map[string]string{SocketKey: target}, rec, func(context.Context) error {
			executed = true
			if got, err := os.Readlink(link); err != nil || got != target {
				t.Errorf("exec before socket publication: %q, %v", got, err)
			}
			return nil
		})
		rt.SocketLink = link
		err := Run(context.Background(), rt)
		if conflict {
			if err == nil || executed || len(rec.calls) != 0 {
				t.Fatalf("socket conflict did not fail closed: %v, exec=%t, calls=%v", err, executed, rec.calls)
			}
		} else if !executed {
			t.Fatalf("agent did not exec: %v", err)
		}
	}
}
