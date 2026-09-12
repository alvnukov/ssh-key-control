package sshconfig

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// ManagedConfig owns a global prefix in an OpenSSH client configuration.
// New directories use 0700 and files use 0600; existing config permission bits
// are preserved (special bits are dropped). Backups are exclusive, retained,
// and never overwritten. Callers must serialize changes to the config and its
// directory; this API does not lock out concurrent external editors.
type ManagedConfig struct{ Path string }

const legacyMinimalPrefix = "# BEGIN ssh-askpass managed config\nAddKeysToAgent confirm\n# END ssh-askpass managed config\n"

// SocketPath is the stable link maintained by the launch agent next to config.
func (c ManagedConfig) SocketPath() string {
	return filepath.Join(filepath.Dir(c.Path), "ssh-key-control.sock")
}

func (c ManagedConfig) prefix() (string, error) {
	path := c.SocketPath()
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "\r\n\x00$") {
		return "", fmt.Errorf("unsupported SSH agent socket path %q", path)
	}
	// OpenSSH expands percent tokens even inside quotes.
	path = strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "%", "%%").Replace(path)
	return "# BEGIN ssh-key-control managed config\nAddKeysToAgent confirm\nIdentityAgent \"" + path + "\"\nPreferredAuthentications publickey\n# END ssh-key-control managed config\n", nil
}

func (c ManagedConfig) legacyPrefixes() ([]string, error) {
	path := filepath.Join(filepath.Dir(c.Path), "ssh-askpass.sock")
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "\r\n\x00$") {
		return nil, fmt.Errorf("unsupported previous SSH agent socket path %q", path)
	}
	path = strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "%", "%%").Replace(path)
	prefix := "# BEGIN ssh-askpass managed config\nAddKeysToAgent confirm\nIdentityAgent \"" + path + "\"\nPreferredAuthentications publickey\n# END ssh-askpass managed config\n"
	return []string{
		prefix,
		strings.Replace(prefix, "PreferredAuthentications publickey", "NumberOfPasswordPrompts 1", 1),
		strings.Replace(prefix, "PreferredAuthentications publickey\n", "", 1),
		legacyMinimalPrefix,
	}, nil
}

// LegacyMigrationNeeded reports whether Path begins with a byte-exact block
// written by a previous SSH Key Control installation. It never changes Path.
func (c ManagedConfig) LegacyMigrationNeeded() (bool, error) {
	data, _, err := c.read()
	if err != nil {
		return false, err
	}
	legacy, err := c.legacyOwned(data)
	if err != nil {
		return false, err
	}
	if legacy > 0 {
		return true, nil
	}
	_, err = c.owned(data)
	return false, err
}

// MigrationBackupPath is the retained, private copy made before migration.
func (c ManagedConfig) MigrationBackupPath() string { return c.Path + ".ssh-key-control.migration.bak" }

// MigrateLegacy replaces only a byte-exact previous managed prefix. The rest
// of the SSH configuration and its mode are preserved exactly.
func (c ManagedConfig) MigrateLegacy() error {
	data, info, err := c.read()
	if err != nil {
		return err
	}
	legacy, err := c.legacyOwned(data)
	if err != nil {
		return err
	}
	if legacy == 0 {
		installed, installErr := c.Installed()
		if installErr != nil {
			return installErr
		}
		if installed {
			return nil
		}
		return fmt.Errorf("SSH config %q does not contain a recognized previous managed prefix", c.Path)
	}
	prefix, err := c.prefix()
	if err != nil {
		return err
	}
	if err := c.backupAt(c.MigrationBackupPath(), data); err != nil {
		return err
	}
	return c.replace(data, append([]byte(prefix), data[legacy:]...), info)
}

// Install prepends managed global directives without changing existing scope.
func (c ManagedConfig) Install() error {
	data, info, err := c.read()
	if err != nil {
		return err
	}
	owned, err := c.owned(data)
	if err != nil {
		return err
	}
	prefix, err := c.prefix()
	if err != nil {
		return err
	}
	if bytes.HasPrefix(data, []byte(prefix)) {
		return nil
	}
	if info != nil && owned == 0 {
		if err := c.backup(data); err != nil {
			return err
		}
	}
	return c.replace(data, append([]byte(prefix), data[owned:]...), info)
}

// Installed reports whether the exact current managed prefix is present.
// It is read-only: malformed ownership markers are returned as an error.
func (c ManagedConfig) Installed() (bool, error) {
	data, _, err := c.read()
	if err != nil {
		return false, err
	}
	if _, err := c.owned(data); err != nil {
		return false, err
	}
	prefix, err := c.prefix()
	if err != nil {
		return false, err
	}
	return bytes.HasPrefix(data, []byte(prefix)), nil
}

// CheckUninstall validates ownership without changing routing.
func (c ManagedConfig) CheckUninstall() error {
	data, _, err := c.read()
	if err != nil {
		return err
	}
	_, err = c.owned(data)
	return err
}

// Uninstall removes only the owned prefix, retaining later edits and the backup.
func (c ManagedConfig) Uninstall() error {
	data, info, err := c.read()
	if err != nil {
		return err
	}
	owned, err := c.owned(data)
	if err != nil {
		return err
	}
	if owned == 0 {
		return nil
	}
	return c.replace(data, data[owned:], info)
}

// The ownership vocabulary is reserved even in malformed or displaced markers.
// Only a byte-exact prefix is removable; suspicious text is never repaired.
func (c ManagedConfig) owned(data []byte) (int, error) {
	prefix, err := c.prefix()
	if err != nil {
		return 0, err
	}
	owned := 0
	passwordVariant := strings.Replace(prefix, "PreferredAuthentications publickey", "NumberOfPasswordPrompts 1", 1)
	routingVariant := strings.Replace(prefix, "PreferredAuthentications publickey\n", "", 1)
	for _, candidate := range []string{prefix, passwordVariant, routingVariant} {
		if bytes.HasPrefix(data, []byte(candidate)) {
			owned = len(candidate)
			break
		}
	}
	if owned == 0 {
		for _, line := range bytes.Split(data, []byte("\n")) {
			if bytes.HasPrefix(line, []byte("# BEGIN ")) && bytes.HasSuffix(line, []byte(" managed config")) {
				return 0, fmt.Errorf("SSH config %q has an unknown managed SSH config prefix; migrate or remove it explicitly before installing", c.Path)
			}
		}
	}
	rest := data[owned:]
	if bytes.Contains(rest, []byte("ssh-key-control managed config")) || bytes.Contains(rest, []byte("# BEGIN ssh-key-control")) || bytes.Contains(rest, []byte("# END ssh-key-control")) {
		return 0, fmt.Errorf("SSH config %q has malformed, modified, displaced or duplicate ownership markers", c.Path)
	}
	return owned, nil
}

func (c ManagedConfig) legacyOwned(data []byte) (int, error) {
	prefixes, err := c.legacyPrefixes()
	if err != nil {
		return 0, err
	}
	owned := 0
	for _, prefix := range prefixes {
		if bytes.HasPrefix(data, []byte(prefix)) {
			owned = len(prefix)
			break
		}
	}
	if owned == 0 {
		return 0, nil
	}
	rest := data[owned:]
	for _, marker := range []string{"ssh-askpass managed config", "# BEGIN ssh-askpass", "# END ssh-askpass", "ssh-key-control managed config", "# BEGIN ssh-key-control", "# END ssh-key-control"} {
		if bytes.Contains(rest, []byte(marker)) {
			return 0, fmt.Errorf("SSH config %q has malformed, modified, displaced or duplicate ownership markers", c.Path)
		}
	}
	return owned, nil
}

// regularManagedFile uses Lstat so dangling links are not treated as missing.
func regularManagedFile(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect SSH config file %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("SSH config file %q is not a regular file (symlinks refused)", path)
	}
	return info, nil
}

func (c ManagedConfig) read() ([]byte, os.FileInfo, error) {
	if _, err := regularManagedFile(c.Path + ".ssh-key-control.bak"); err != nil {
		return nil, nil, err
	}
	info, err := regularManagedFile(c.Path)
	if err != nil || info == nil {
		return nil, info, err
	}
	// O_NOFOLLOW closes the leaf-symlink race; O_NONBLOCK avoids hanging if a
	// FIFO is substituted between inspection and open.
	f, err := os.OpenFile(c.Path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open SSH config %q: %w", c.Path, err)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("stat open SSH config %q: %w", c.Path, err)
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, nil, fmt.Errorf("SSH config %q changed while opening", c.Path)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, nil, fmt.Errorf("read SSH config %q: %w", c.Path, err)
	}
	return data, opened, nil
}

// backup saves the pre-install contents only; uninstall never creates a backup.
func (c ManagedConfig) backup(original []byte) error {
	return c.backupAt(c.Path+".ssh-key-control.bak", original)
}

func (c ManagedConfig) backupAt(backup string, original []byte) error {
	f, err := os.OpenFile(backup, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("create SSH config backup %q: %w", backup, err)
		}
		// The install backup retains the original contents across reinstallations.
		// Migration backups must instead match the exact input being migrated.
		if backup == c.Path+".ssh-key-control.bak" {
			_, checkErr := regularManagedFile(backup)
			return checkErr
		}
		existing, readErr := readRegularFile(backup)
		if readErr != nil {
			return readErr
		}
		if !bytes.Equal(existing, original) {
			return fmt.Errorf("SSH config backup %q already exists with different contents", backup)
		}
		return nil
	}
	_, writeErr := f.Write(original)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil {
		_ = os.Remove(backup)
		return fmt.Errorf("write SSH config backup %q: %w", backup, writeErr)
	}
	if closeErr != nil {
		_ = os.Remove(backup)
		return fmt.Errorf("close SSH config backup %q: %w", backup, closeErr)
	}
	return nil
}

func readRegularFile(path string) ([]byte, error) {
	info, err := regularManagedFile(path)
	if err != nil {
		return nil, err
	}
	if info == nil {
		return nil, os.ErrNotExist
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open SSH config backup %q: %w", path, err)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, fmt.Errorf("SSH config backup %q changed while opening", path)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read SSH config backup %q: %w", path, err)
	}
	return data, nil
}

func (c ManagedConfig) replace(original, replacement []byte, info os.FileInfo) error {
	mode := os.FileMode(0600)
	if info != nil {
		mode = info.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(c.Path), 0700); err != nil {
		return fmt.Errorf("create SSH config directory: %w", err)
	}
	temp, err := os.CreateTemp(filepath.Dir(c.Path), ".ssh-key-control-config-*")
	if err != nil {
		return fmt.Errorf("create temporary SSH config: %w", err)
	}
	defer os.Remove(temp.Name())
	defer temp.Close()
	if _, err := temp.Write(replacement); err != nil {
		return fmt.Errorf("write temporary SSH config: %w", err)
	}
	if err := temp.Chmod(mode); err != nil {
		return fmt.Errorf("chmod temporary SSH config: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync temporary SSH config: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary SSH config: %w", err)
	}
	current, currentInfo, err := c.read()
	if err != nil {
		return err
	}
	if (info == nil) != (currentInfo == nil) || (info != nil && !os.SameFile(info, currentInfo)) || !bytes.Equal(current, original) {
		return fmt.Errorf("SSH config %q changed before replacement", c.Path)
	}
	if err := os.Rename(temp.Name(), c.Path); err != nil {
		return fmt.Errorf("replace SSH config %q: %w", c.Path, err)
	}
	return nil
}
