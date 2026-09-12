// Package nativemonitor observes and removes identities from Apple's agent.
// It is reactive hygiene, not a boundary against another process of the user.
package nativemonitor

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const PolicyFile = "native-agent-monitor.json"
const StateFile = "native-agent-monitor-state.json"

type Policy struct {
	Enabled bool `json:"enabled"`
}
type State struct {
	Enabled   bool      `json:"enabled"`
	Session   string    `json:"session"`
	CheckedAt time.Time `json:"checkedAt"`
	Status    string    `json:"status"`
	Removed   uint64    `json:"removed"`
	Failed    uint64    `json:"failed"`
}

func readPrivate(path string, out any) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 8192 {
		return errors.New("monitor file must be a bounded private regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil {
		return err
	}
	if len(data) > 8192 {
		return errors.New("monitor file too large")
	}
	return json.Unmarshal(data, out)
}
func ReadPolicy(dir string) (Policy, error) {
	var p Policy
	err := readPrivate(filepath.Join(dir, PolicyFile), &p)
	if os.IsNotExist(err) {
		p.Enabled = true
		err = nil
	}
	return p, err
}
func ReadState(dir string) (State, error) {
	var s State
	err := readPrivate(filepath.Join(dir, StateFile), &s)
	return s, err
}
func writePrivate(dir, name string, value any) error {
	if dir == "" {
		return errors.New("application support directory unavailable")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("monitor directory must not be a symlink")
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".monitor-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), filepath.Join(dir, name))
}
func SavePolicy(dir string, p Policy) error { return writePrivate(dir, PolicyFile, p) }
func SaveState(dir string, s State) error   { return writePrivate(dir, StateFile, s) }
