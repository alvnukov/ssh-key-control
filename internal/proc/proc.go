// Package proc describes the chain of processes behind a request: the process
// holding the other end of a socket, and its ancestors.
//
// A link is identified by the kernel's (PID, Version) pair. Version is the
// PID version, which distinguishes a recycled PID from the original process
// and changes when a process replaces its image, so neither waiting for a PID
// to come round again nor exec'ing a different program inherits anything.
// Names and paths are display only: a process chooses its own.
package proc

import (
	"strconv"
	"strings"
	"time"
)

// NoTTY is the device number of a process with no controlling terminal.
const NoTTY = ^uint32(0)

// How much older an ancestor must be than its child to count as the durable
// part of the session: an order of magnitude, and at least half a minute.
// The ratio alone fires between two infants (5ms and 80ms differ sixteenfold).
const (
	ageRatio   = 10
	ageMinimum = 30 * time.Second
)

// maxDepth bounds the walk. A deeper tree cannot be shown in a dialog anyway.
const maxDepth = 64

// Link is one process. PID and Version identify it; everything else describes
// it. Version is zero when the kernel would not say, which is what happens for
// a process owned by another user; such a link is pinned by its PID and Name.
type Link struct {
	PID     int32
	Version uint32
	// Name is the kernel's short command name, always available and stable
	// for the life of the process. Path is the executable, which is empty
	// once the file behind a running program has been replaced or unlinked.
	Name string
	Path string
	// TTY is the controlling terminal, meaningful only when TTYKnown.
	TTY      uint32
	TTYKnown bool
	// Start is the process start time, zero when the kernel would not say.
	Start time.Time
	// Identifier and Team come from a code signature that macOS validated.
	// Verified is false when none could be read, which is normal for a
	// program that updates itself in place.
	Identifier string
	Team       string
	Verified   bool
}

// Display names the process for a human: its executable, or failing that the
// short name the kernel keeps.
func (l Link) Display() string {
	if i := strings.LastIndexByte(l.Path, '/'); i >= 0 && i+1 < len(l.Path) {
		return l.Path[i+1:]
	}
	if l.Path != "" {
		return l.Path
	}
	return l.Name
}

// Same reports that two links describe one process. The PID version settles
// it whenever the kernel gave one; for a link it would not version, the short
// command name is all there ever was to compare.
func (l Link) Same(other Link) bool {
	if l.PID != other.PID {
		return false
	}
	if l.Version != 0 || other.Version != 0 {
		return l.Version == other.Version
	}
	return l.Name == other.Name
}

// Chain runs from the process that made the request upward through its
// ancestors, stopping below the root of the process tree. Complete reports
// that the walk got that far: a chain cut short by an unreadable parent may
// be hiding the very ancestor a decision should have been attached to.
type Chain struct {
	Links    []Link
	Complete bool
}

// Empty reports that nothing is known about the caller.
func (c Chain) Empty() bool { return len(c.Links) == 0 }

// Boundary reports the lowest link a temporary decision may attach to: the
// nearest ancestor that was already running when this command began, and so
// will outlive it. It reports false when no such ancestor can be named, which
// leaves the request unanchored.
//
// Two independent signals are read and the lower cut wins, so the decision is
// always the narrower of the two readings. A different controlling terminal
// means a session began there; an ancestor an order of magnitude older than
// its child was already waiting when the child started. Neither signal is
// enough alone: the terminal alone puts an entire terminal application inside
// one decision, and age alone finds nothing in a pane where every process is
// a second old.
func (c Chain) Boundary(now time.Time) (int, bool) {
	links := c.Links
	if len(links) < 2 {
		return 0, false
	}
	cut, found := len(links), false
	if tty := links[0]; tty.TTYKnown && tty.TTY != NoTTY {
		for i := 1; i < len(links); i++ {
			if links[i].TTYKnown && links[i].TTY != tty.TTY {
				cut, found = i, true
				break
			}
		}
	}
	for i := 1; i < cut; i++ {
		child, parent := age(now, links[i-1]), age(now, links[i])
		// An age we were not given is never turned into a cut: claiming a
		// boundary we did not measure would narrow a decision on a guess.
		if child < 0 || parent < 0 {
			continue
		}
		if parent >= child*ageRatio && parent-child >= ageMinimum {
			cut, found = i, true
			break
		}
	}
	if !found {
		// Nothing tells these processes apart. The furthest ancestor we
		// reached is still a real anchor, but only if the walk finished:
		// a parent we could not read might have been the durable one.
		if !c.Complete {
			return 0, false
		}
		cut = len(links) - 1
	}
	return cut, cut > 0
}

func age(now time.Time, l Link) time.Duration {
	if l.Start.IsZero() {
		return -1
	}
	return now.Sub(l.Start)
}

// Anchor is the part of the chain a decision is remembered against: the
// boundary link and every ancestor above it.
func (c Chain) Anchor(boundary int) Chain {
	if boundary < 0 || boundary >= len(c.Links) {
		return Chain{}
	}
	return Chain{Links: c.Links[boundary:], Complete: c.Complete}
}

// Fingerprint identifies an ancestry exactly. It is neither a secret nor a
// capability: it only has to tell one live chain of processes from another.
// Two chains with the same fingerprint are the same processes, in the same
// order, still running the same programs.
func (c Chain) Fingerprint() string {
	if len(c.Links) == 0 {
		return ""
	}
	var b strings.Builder
	for i, l := range c.Links {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(strconv.Itoa(int(l.PID)))
		b.WriteByte('/')
		b.WriteString(strconv.FormatUint(uint64(l.Version), 10))
		// A process the kernel would not version is pinned by its name as
		// well. On its own that is weak, but a chain is walked from the
		// live caller upward, so a link can only appear here while it is
		// genuinely the parent of the link below it: a recycled PID cannot
		// take a place in the middle of a real ancestry.
		if l.Version == 0 {
			b.WriteByte('/')
			b.WriteString(strconv.Quote(l.Name))
		}
	}
	return b.String()
}
