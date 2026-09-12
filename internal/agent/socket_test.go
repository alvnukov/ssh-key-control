package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPublishSocketCreatesAndRefreshesLink(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "config", "ssh-key-control.sock")
	for _, name := range []string{"old-socket", "new-socket"} {
		target := filepath.Join(dir, name)
		if err := PublishSocket(link, target); err != nil {
			t.Fatal(err)
		}
		if got, err := os.Readlink(link); err != nil || got != target {
			t.Fatalf("link = %q, %v; want %q", got, err, target)
		}
	}
	info, err := os.Stat(filepath.Dir(link))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 {
		t.Errorf("parent permissions = %o, want 700", info.Mode().Perm())
	}
	entries, err := os.ReadDir(filepath.Dir(link))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "ssh-key-control.sock" {
		t.Errorf("unexpected entries after publishing: %v", entries)
	}
}

func TestPublishSocketRefusesNonLink(t *testing.T) {
	for _, directory := range []bool{false, true} {
		name := "file"
		if directory {
			name = "directory"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			link := filepath.Join(dir, "ssh-key-control.sock")
			if directory {
				if err := os.Mkdir(link, 0700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(link, []byte("keep me"), 0600); err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(link)
			if err != nil {
				t.Fatal(err)
			}
			if err := PublishSocket(link, filepath.Join(dir, "target")); err == nil {
				t.Fatal("publishing over a non-symlink succeeded")
			}
			after, err := os.Lstat(link)
			if err != nil || !os.SameFile(before, after) {
				t.Fatalf("non-symlink was replaced: %v", err)
			}
			if !directory {
				if data, err := os.ReadFile(link); err != nil || string(data) != "keep me" {
					t.Fatalf("file changed: %q, %v", data, err)
				}
			}
		})
	}
}

func TestPublishSocketRefusesInvalidTarget(t *testing.T) {
	for _, kind := range []string{"empty", "relative", "file", "directory"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			link := filepath.Join(dir, "config", "ssh-key-control.sock")
			target := ""
			switch kind {
			case "relative":
				target = "relative.sock"
			case "file":
				target = filepath.Join(dir, "target")
				if err := os.WriteFile(target, []byte("keep me"), 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				target = dir
			}
			if err := PublishSocket(link, target); err == nil {
				t.Fatal("invalid target accepted")
			}
			if _, err := os.Lstat(filepath.Dir(link)); !os.IsNotExist(err) {
				t.Fatalf("invalid target created link parent: %v", err)
			}
			if kind == "file" {
				if data, err := os.ReadFile(target); err != nil || string(data) != "keep me" {
					t.Fatalf("target changed: %q, %v", data, err)
				}
			}
		})
	}
}

func TestPublishSocketRefusesForeignLinkTarget(t *testing.T) {
	for _, kind := range []string{"file", "directory"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			link := filepath.Join(dir, "ssh-key-control.sock")
			foreign := filepath.Join(dir, "foreign")
			if kind == "directory" {
				if err := os.Mkdir(foreign, 0700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(foreign, []byte("keep me"), 0600); err != nil {
				t.Fatal(err)
			}
			// Relative existing links must be resolved from their parent.
			if err := os.Symlink("foreign", link); err != nil {
				t.Fatal(err)
			}
			if err := PublishSocket(link, filepath.Join(dir, "new-socket")); err == nil {
				t.Fatal("foreign link target accepted")
			}
			if got, err := os.Readlink(link); err != nil || got != "foreign" {
				t.Fatalf("foreign link changed: %q, %v", got, err)
			}
			if kind == "file" {
				if data, err := os.ReadFile(foreign); err != nil || string(data) != "keep me" {
					t.Fatalf("foreign target changed: %q, %v", data, err)
				}
			} else if info, err := os.Stat(foreign); err != nil || !info.IsDir() {
				t.Fatalf("foreign directory changed: %v", err)
			}
		})
	}
}

func TestRemoveSocketRemovesOnlyLink(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "ssh-key-control.sock")
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep me"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := RemoveSocket(link); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(link); !os.IsNotExist(err) {
			t.Fatalf("link still exists: %v", err)
		}
		if data, err := os.ReadFile(target); err != nil || string(data) != "keep me" {
			t.Fatalf("target changed: %q, %v", data, err)
		}
	}
	if err := os.Symlink(filepath.Join(dir, "missing"), link); err != nil {
		t.Fatal(err)
	}
	if err := RemoveSocket(link); err != nil {
		t.Fatalf("remove dangling link: %v", err)
	}
}
