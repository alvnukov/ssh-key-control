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
	backup := c.Path + ".ssh-key-control.bak"
	f, err := os.OpenFile(backup, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("create SSH config backup %q: %w", backup, err)
		}
		_, err := regularManagedFile(backup)
		return err
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
