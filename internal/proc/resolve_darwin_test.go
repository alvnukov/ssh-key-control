//go:build darwin && cgo

package proc_test

import (
	"os"
	"testing"
	"time"

	"github.com/alvnukov/ssh-key-control/internal/proc"
)

// These run against this test process's own real ancestry, which is the only
// thing that can show the kernel is being read correctly. What that ancestry
// contains depends on how the tests were started, so the assertions are about
// its shape rather than about any particular program being in it.
func TestResolveReadsThisProcessAncestry(t *testing.T) {
	self := int32(os.Getpid())
	chain := proc.Resolve(self, 0)
	if len(chain.Links) < 2 {
		t.Fatalf("resolved %d links for the test process, want its ancestors too", len(chain.Links))
	}
	if chain.Links[0].PID != self {
		t.Fatalf("chain starts at %d, want this process %d", chain.Links[0].PID, self)
	}
	if chain.Links[0].Version == 0 {
		t.Fatal("the kernel gave no pid version for this process")
	}
	seen := map[int32]bool{}
	for i, l := range chain.Links {
		if l.PID <= 1 {
			t.Fatalf("link %d is pid %d; the root of the tree is not a process anyone owns", i, l.PID)
		}
		if seen[l.PID] {
			t.Fatalf("pid %d appears twice: the walk went in a circle", l.PID)
		}
		seen[l.PID] = true
		// A process owned by another user tells us almost nothing, but the
		// kernel always gives up its name, and the walk must carry on past it.
		if l.Name == "" {
			t.Fatalf("link %d (pid %d) has no name", i, l.PID)
		}
		if l.Display() == "" {
			t.Fatalf("link %d (pid %d) cannot be shown to anyone", i, l.PID)
		}
	}
	if _, ok := chain.Boundary(time.Now()); !ok && chain.Complete {
		t.Log("no anchor in this ancestry; acceptable, but worth knowing")
	}
}

func TestResolveRejectsAProcessThatReplacedItsImage(t *testing.T) {
	self := int32(os.Getpid())
	version := proc.Resolve(self, 0).Links[0].Version
	if chain := proc.Resolve(self, version); len(chain.Links) == 0 {
		t.Fatal("the right pid version was rejected")
	}
	if chain := proc.Resolve(self, version+1); len(chain.Links) != 0 {
		t.Fatal("a stale pid version still resolved a chain")
	}
}

func TestResolveGivesUpQuietlyOnAProcessThatIsGone(t *testing.T) {
	// Not an error: a caller that has already exited is simply unanchorable.
	if chain := proc.Resolve(0x7FFFFFF0, 0); len(chain.Links) != 0 {
		t.Fatalf("resolved %d links for a pid that cannot exist", len(chain.Links))
	}
}

func TestAliveFollowsTheProcessAndNotTheNumber(t *testing.T) {
	self := proc.Resolve(int32(os.Getpid()), 0).Links[0]
	if !proc.Alive(self) {
		t.Fatal("this running process was reported dead")
	}
	recycled := self
	recycled.Version++
	if proc.Alive(recycled) {
		t.Fatal("a different generation of this pid was reported alive")
	}
	gone := self
	gone.PID = 0x7FFFFFF0
	if proc.Alive(gone) {
		t.Fatal("a pid that cannot exist was reported alive")
	}
}

func TestDescribeAddsIdentitiesWithoutChangingTheChain(t *testing.T) {
	chain := proc.Resolve(int32(os.Getpid()), 0)
	described := proc.Describe(chain)
	if described.Fingerprint() != chain.Fingerprint() {
		t.Fatal("describing a chain changed which processes it names")
	}
	for i, l := range described.Links {
		if l.Verified && l.Identifier == "" {
			t.Fatalf("link %d is marked verified with no signing identity", i)
		}
	}
}
