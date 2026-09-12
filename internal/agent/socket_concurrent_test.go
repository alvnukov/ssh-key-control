package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPublishSocketConcurrentPublication(t *testing.T) {
	for _, same := range []bool{true, false} {
		dir := t.TempDir()
		link, target := filepath.Join(dir, "link"), filepath.Join(dir, "socket")
		other := target
		if !same {
			other = filepath.Join(dir, "different-socket")
		}
		err := publishSocket(link, target, func() {
			if err := PublishSocket(link, other); err != nil {
				t.Fatal(err)
			}
		})
		if same && err != nil {
			t.Fatalf("identical concurrent publication rejected: %v", err)
		}
		if !same && err == nil {
			t.Fatal("conflicting concurrent publication accepted")
		}
		if got, err := os.Readlink(link); err != nil || got != other {
			t.Fatalf("concurrent publisher's link lost: %q, %v", got, err)
		}
	}
}
