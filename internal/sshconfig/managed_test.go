package sshconfig_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/alvnukov/ssh-key-control/internal/sshconfig"
)

func TestManagedInstallPrecedesOriginalScope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	original := []byte("# keep my comments\nAddKeysToAgent no\nHost example.invalid\n  User alice\nHost other.invalid\n  User bob")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	config := sshconfig.ManagedConfig{Path: path}
	if err := config.Install(); err != nil {
		t.Fatal(err)
	}
	installed := readManagedFile(t, path)
	expectedPrefix := fmt.Sprintf("# BEGIN ssh-key-control managed config\nAddKeysToAgent confirm\nIdentityAgent %q\nPreferredAuthentications publickey\n# END ssh-key-control managed config\n", config.SocketPath())
	if !bytes.Equal(installed, append([]byte(expectedPrefix), original...)) {
		t.Fatalf("unexpected managed global prefix: %q", installed)
	}
	if !bytes.HasSuffix(installed, original) || bytes.Equal(installed, original) {
		t.Fatalf("original bytes not preserved after prefix: %q", installed)
	}
	out, err := exec.Command("/usr/bin/ssh", "-G", "-F", path, "example.invalid").CombinedOutput()
	if err != nil {
		t.Fatalf("ssh -G: %v: %s", err, out)
	}
	if !strings.Contains(string(out), "addkeystoagent confirm\n") || !strings.Contains(string(out), "user alice\n") {
		t.Fatalf("wrong effective config: %s", out)
	}
	if err := config.Install(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(installed, readManagedFile(t, path)) {
		t.Fatal("install is not idempotent")
	}
}

func TestManagedRefusesUnsafeFiles(t *testing.T) {
	for _, install := range []bool{true, false} {
		for _, slot := range []string{"config", "backup"} {
			for _, kind := range []string{"symlink", "dangling symlink", "directory", "fifo"} {
				t.Run(fmt.Sprintf("%t/%s/%s", install, slot, kind), func(t *testing.T) {
					dir := t.TempDir()
					path := filepath.Join(dir, "config")
					config := sshconfig.ManagedConfig{Path: path}
					if err := config.Install(); err != nil {
						t.Fatal(err)
					}
					if install {
						if err := config.Uninstall(); err != nil {
							t.Fatal(err)
						}
					}
					original := readManagedFile(t, path)
					target := filepath.Join(dir, "target")
					targetData := []byte("# do not touch\n")
					if kind != "dangling symlink" {
						if err := os.WriteFile(target, targetData, 0600); err != nil {
							t.Fatal(err)
						}
					}
					unsafe := path
					if slot == "backup" {
						unsafe += ".ssh-key-control.bak"
					}
					if err := os.Remove(unsafe); err != nil && !os.IsNotExist(err) {
						t.Fatal(err)
					}
					if kind == "fifo" {
						if err := syscall.Mkfifo(unsafe, 0600); err != nil {
							t.Fatal(err)
						}
					} else if kind == "directory" {
						if err := os.Mkdir(unsafe, 0700); err != nil {
							t.Fatal(err)
						}
					} else {
						if err := os.Symlink(target, unsafe); err != nil {
							t.Fatal(err)
						}
					}
					var err error
					if install {
						err = config.Install()
					} else {
						err = config.Uninstall()
					}
					if err == nil {
						t.Fatal("accepted unsafe file")
					}
					if slot == "backup" && !bytes.Equal(readManagedFile(t, path), original) {
						t.Fatal("changed original on error")
					}
					if kind != "dangling symlink" && !bytes.Equal(readManagedFile(t, target), targetData) {
						t.Fatal("changed symlink target")
					}
					if kind == "dangling symlink" {
						if _, err := os.Stat(target); !os.IsNotExist(err) {
							t.Fatal("created dangling target")
						}
					}
					info, err := os.Lstat(unsafe)
					if err != nil {
						t.Fatal(err)
					}
					if kind != "directory" && kind != "fifo" && info.Mode()&os.ModeSymlink == 0 {
						t.Fatal("replaced symlink")
					}
				})
			}
		}
	}
}

func TestManagedWriteFailureLeavesOriginal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	for _, install := range []bool{true, false} {
		t.Run(fmt.Sprint(install), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config")
			if err := os.WriteFile(path, []byte("# original\n"), 0600); err != nil {
				t.Fatal(err)
			}
			config := sshconfig.ManagedConfig{Path: path}
			if !install {
				if err := config.Install(); err != nil {
					t.Fatal(err)
				}
			}
			original := readManagedFile(t, path)
			backup := []byte("# existing backup must survive\n")
			if err := os.WriteFile(path+".ssh-key-control.bak", backup, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, 0500); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.Chmod(dir, 0700); err != nil {
					t.Error(err)
				}
			})
			var err error
			if install {
				err = config.Install()
			} else {
				err = config.Uninstall()
			}
			if err == nil || !strings.Contains(err.Error(), "temporary SSH config") {
				t.Fatalf("expected contextual temp-write error, got %v", err)
			}
			if !bytes.Equal(readManagedFile(t, path), original) {
				t.Fatal("write failure changed original")
			}
			if !bytes.Equal(readManagedFile(t, path+".ssh-key-control.bak"), backup) {
				t.Fatal("write failure changed backup")
			}
		})
	}
}

func readManagedFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestManagedUninstallPreservesLaterEditsAndBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	original := []byte("# original\r\nHost *\n  ForwardAgent no\n")
	if err := os.WriteFile(path, original, 0640); err != nil {
		t.Fatal(err)
	}
	config := sshconfig.ManagedConfig{Path: path}
	if err := config.Install(); err != nil {
		t.Fatal(err)
	}
	backup := path + ".ssh-key-control.bak"
	if !bytes.Equal(readManagedFile(t, backup), original) {
		t.Fatal("backup changed original bytes")
	}
	info, err := os.Stat(backup)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("backup mode = %o", info.Mode().Perm())
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0640 {
		t.Fatalf("config mode = %o", info.Mode().Perm())
	}
	appended := []byte("\n# later edit\nHost later.invalid\n  User carol\n")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(appended); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := config.Uninstall(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readManagedFile(t, path), append(original, appended...)) {
		t.Fatal("uninstall discarded user edits")
	}
	if !bytes.Equal(readManagedFile(t, backup), original) {
		t.Fatal("backup overwritten")
	}
	if err := config.Uninstall(); err != nil {
		t.Fatal(err)
	}
	if err := config.Install(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readManagedFile(t, backup), original) {
		t.Fatal("reinstall overwrote backup")
	}
}

func TestManagedFreshHomeAndMissingUninstall(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".ssh", "config")
	config := sshconfig.ManagedConfig{Path: path}
	if err := config.Uninstall(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatalf("missing uninstall created directory: %v", err)
	}
	if err := config.Install(); err != nil {
		t.Fatal(err)
	}
	for name, mode := range map[string]os.FileMode{path: 0600, filepath.Dir(path): 0700} {
		info, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != mode {
			t.Fatalf("%s mode = %o, want %o", name, info.Mode().Perm(), mode)
		}
	}
	if _, err := os.Stat(path + ".ssh-key-control.bak"); !os.IsNotExist(err) {
		t.Fatalf("fresh install backup: %v", err)
	}
	if err := config.Uninstall(); err != nil {
		t.Fatal(err)
	}
	if len(readManagedFile(t, path)) != 0 {
		t.Fatal("fresh uninstall left content")
	}
	if _, err := os.Stat(path + ".ssh-key-control.bak"); !os.IsNotExist(err) {
		t.Fatalf("uninstall created a misleading original backup: %v", err)
	}
}

func TestManagedRejectsAmbiguousOwnership(t *testing.T) {
	const prefix = "# BEGIN ssh-key-control managed config\nAddKeysToAgent confirm\n# END ssh-key-control managed config\n"
	for name, original := range map[string]string{
		"modified directive": strings.Replace(prefix, "confirm", "no", 1),
		"missing end":        "# BEGIN ssh-key-control managed config\nAddKeysToAgent confirm\n",
		"orphan end":         "# END ssh-key-control managed config\n",
		"duplicate":          prefix + prefix,
		"displaced":          "# user comment\n" + prefix,
		"modified marker":    strings.Replace(prefix, "BEGIN", "BEGIN edited", 1),
		"modified newline":   strings.ReplaceAll(prefix, "\n", "\r\n"),
	} {
		for _, install := range []bool{true, false} {
			t.Run(name+fmt.Sprint(install), func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "config")
				if err := os.WriteFile(path, []byte(original), 0600); err != nil {
					t.Fatal(err)
				}
				config := sshconfig.ManagedConfig{Path: path}
				var err error
				if install {
					err = config.Install()
				} else {
					err = config.Uninstall()
				}
				if err == nil {
					t.Fatal("accepted ambiguous ownership")
				}
				if string(readManagedFile(t, path)) != original {
					t.Fatal("modified original on error")
				}
				if _, err := os.Stat(path + ".ssh-key-control.bak"); !os.IsNotExist(err) {
					t.Fatalf("created backup on ownership error: %v", err)
				}
			})
		}
	}
}

func TestManagedPreservesIncludeAndMatchScope(t *testing.T) {
	dir := t.TempDir()
	included := filepath.Join(dir, "included")
	if err := os.WriteFile(included, []byte("AddKeysToAgent no\nUser included-user\n"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config")
	original := []byte(fmt.Sprintf("Include %q\nMatch host example.invalid\n  Port 2222\nHost other.invalid\n  Port 2200\n", included))
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	config := sshconfig.ManagedConfig{Path: path}
	if err := config.Install(); err != nil {
		t.Fatal(err)
	}
	for host, port := range map[string]string{"example.invalid": "2222", "other.invalid": "2200"} {
		out, err := exec.Command("/usr/bin/ssh", "-G", "-F", path, host).CombinedOutput()
		if err != nil {
			t.Fatalf("ssh -G: %v: %s", err, out)
		}
		for _, want := range []string{"addkeystoagent confirm\n", "user included-user\n", "port " + port + "\n"} {
			if !strings.Contains(string(out), want) {
				t.Errorf("%s lacks %q: %s", host, want, out)
			}
		}
	}
	if err := config.Uninstall(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readManagedFile(t, path), original) {
		t.Fatal("uninstall changed Include/Match configuration")
	}
}

func TestManagedMigratesExactPreviousPrefixes(t *testing.T) {
	for _, variant := range []string{"current", "password", "routing", "minimal"} {
		t.Run(variant, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config")
			oldSocket := filepath.Join(dir, "ssh-askpass.sock")
			prefix := fmt.Sprintf("# BEGIN ssh-askpass managed config\nAddKeysToAgent confirm\nIdentityAgent %q\nPreferredAuthentications publickey\n# END ssh-askpass managed config\n", oldSocket)
			switch variant {
			case "password":
				prefix = strings.Replace(prefix, "PreferredAuthentications publickey", "NumberOfPasswordPrompts 1", 1)
			case "routing":
				prefix = strings.Replace(prefix, "PreferredAuthentications publickey\n", "", 1)
			case "minimal":
				prefix = "# BEGIN ssh-askpass managed config\nAddKeysToAgent confirm\n# END ssh-askpass managed config\n"
			}
			suffix := []byte("# user's bytes stay exact\r\nHost example.invalid\n  Port 2222\n")
			original := append([]byte(prefix), suffix...)
			if err := os.WriteFile(path, original, 0640); err != nil {
				t.Fatal(err)
			}
			config := sshconfig.ManagedConfig{Path: path}
			needed, err := config.LegacyMigrationNeeded()
			if err != nil || !needed {
				t.Fatalf("migration status = %t, %v", needed, err)
			}
			if err := config.Install(); err == nil || !strings.Contains(err.Error(), "unknown managed SSH config prefix") {
				t.Fatalf("ordinary install bypassed consent: %v", err)
			}
			if !bytes.Equal(readManagedFile(t, path), original) {
				t.Fatal("ordinary install changed previous configuration")
			}
			if err := config.MigrateLegacy(); err != nil {
				t.Fatal(err)
			}
			installed := readManagedFile(t, path)
			if !bytes.HasSuffix(installed, suffix) {
				t.Fatal("migration changed user SSH directives")
			}
			if !bytes.Equal(readManagedFile(t, config.MigrationBackupPath()), original) {
				t.Fatal("migration backup does not contain exact original")
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0640 {
				t.Fatalf("mode after migration = %v, %v", info, err)
			}
			if err := config.MigrateLegacy(); err != nil {
				t.Fatalf("migration is not safely resumable: %v", err)
			}
		})
	}
}

func TestManagedMigrationRefusesUnknownOrAmbiguousPrefixes(t *testing.T) {
	for name, original := range map[string]string{
		"foreign":   "# BEGIN previous-product managed config\nAddKeysToAgent confirm\n# END previous-product managed config\nHost *\n",
		"modified":  "# BEGIN ssh-askpass managed config\nAddKeysToAgent no\n# END ssh-askpass managed config\nHost *\n",
		"displaced": "# user comment\n# BEGIN ssh-askpass managed config\nAddKeysToAgent confirm\n# END ssh-askpass managed config\n",
		"duplicate": "# BEGIN ssh-askpass managed config\nAddKeysToAgent confirm\n# END ssh-askpass managed config\n# BEGIN ssh-askpass managed config\nAddKeysToAgent confirm\n# END ssh-askpass managed config\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config")
			if err := os.WriteFile(path, []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			config := sshconfig.ManagedConfig{Path: path}
			if needed, err := config.LegacyMigrationNeeded(); err == nil || needed {
				t.Fatalf("unsafe prefix classified as migratable: %t, %v", needed, err)
			}
			if err := config.MigrateLegacy(); err == nil {
				t.Fatal("unsafe prefix migrated")
			}
			if got := readManagedFile(t, path); string(got) != original {
				t.Fatal("unsafe migration changed config")
			}
			if _, err := os.Stat(config.MigrationBackupPath()); !os.IsNotExist(err) {
				t.Fatalf("unsafe migration created backup: %v", err)
			}
		})
	}
}

func TestManagedMigrationDoesNotOverwriteDifferentBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	original := []byte("# BEGIN ssh-askpass managed config\nAddKeysToAgent confirm\n# END ssh-askpass managed config\nHost *\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	config := sshconfig.ManagedConfig{Path: path}
	if err := os.WriteFile(config.MigrationBackupPath(), []byte("different"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := config.MigrateLegacy(); err == nil || !strings.Contains(err.Error(), "different contents") {
		t.Fatalf("migration error = %v", err)
	}
	if !bytes.Equal(readManagedFile(t, path), original) {
		t.Fatal("backup conflict changed config")
	}
}
