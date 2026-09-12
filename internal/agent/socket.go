package agent

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
)

// PublishSocket atomically publishes a stable link to the launchd socket.
// The target must be absolute; missing targets are allowed for stale sockets,
// but existing targets (including the old link's target) must be Unix sockets.
// Concurrent publication of the identical target is safe. Callers must serialize
// changes to different targets and to the parent directory. The pre-rename check
// is best effort, not a lock against hostile writers. Targets are never modified.
func PublishSocket(linkPath, target string) error {
	return publishSocket(linkPath, target, nil)
}

// beforeCommit exposes the competing-publication boundary to deterministic tests.
func publishSocket(linkPath, target string, beforeCommit func()) error {
	if !filepath.IsAbs(target) {
		return fmt.Errorf("socket target must be a nonempty absolute path: %q", target)
	}
	if err := checkSocketTarget(target); err != nil {
		return err
	}
	before, err := socketLinkInfo(linkPath)
	if err != nil {
		return err
	}
	if before != nil {
		if err := checkSocketTarget(linkPath); err != nil {
			return err
		}
	}
	dir := filepath.Dir(linkPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create socket link parent: %w", err)
	}
	temp := filepath.Join(dir, ".ssh-key-control-socket-"+rand.Text())
	if err := os.Symlink(target, temp); err != nil {
		return fmt.Errorf("create temporary socket link: %w", err)
	}
	defer os.Remove(temp)
	// Recheck without following the leaf: do not knowingly replace a link
	// that changed since inspection, or a path another owner just created.
	if beforeCommit != nil {
		beforeCommit()
	}
	after, err := socketLinkInfo(linkPath)
	if err != nil {
		return err
	}
	if (before == nil) != (after == nil) || (before != nil && !os.SameFile(before, after)) {
		// CLI installation and agent startup may both publish this same socket.
		// An identical winner has already completed our work; do not replace it.
		if after != nil {
			if current, err := os.Readlink(linkPath); err == nil && current == target {
				return nil
			}
		}
		return fmt.Errorf("socket link %q changed before publication", linkPath)
	}
	if err := os.Rename(temp, linkPath); err != nil {
		return fmt.Errorf("publish socket link: %w", err)
	}
	return nil
}

// RemoveSocket removes only the designated symlink, never its target. A missing
// link is a no-op; non-symlinks are refused. As with PublishSocket, callers must
// serialize ownership of the link path and its parent directory.
func RemoveSocket(linkPath string) error {
	info, err := socketLinkInfo(linkPath)
	if err != nil || info == nil {
		return err
	}
	if err := os.Remove(linkPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove socket link: %w", err)
	}
	return nil
}

func socketLinkInfo(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect socket link: %w", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return nil, fmt.Errorf("refuse non-symlink socket link %q", path)
	}
	return info, nil
}

func checkSocketTarget(path string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil // launchd may have retired the previous socket already.
	}
	if err != nil {
		return fmt.Errorf("inspect socket target %q: %w", path, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refuse non-socket target %q", path)
	}
	return nil
}
