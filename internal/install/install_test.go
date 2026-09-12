package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alvnukov/ssh-key-control/internal/agent"
	"github.com/alvnukov/ssh-key-control/internal/launchd"
	"github.com/alvnukov/ssh-key-control/internal/launchd/launchdtest"
)

// memFS keeps files in a map.
type memFS struct {
	files map[string][]byte
	dirs  map[string]bool
}

func newMemFS() *memFS { return &memFS{files: map[string][]byte{}, dirs: map[string]bool{}} }

func (m *memFS) MkdirAll(path string, _ os.FileMode) error { m.dirs[path] = true; return nil }
func (m *memFS) WriteFile(path string, data []byte, _ os.FileMode) error {
	if !m.dirs[filepath.Dir(path)] {
		return fmt.Errorf("%s: no such directory", filepath.Dir(path))
	}
	m.files[path] = data
	return nil
}
func (m *memFS) Remove(path string) error {
	if _, ok := m.files[path]; !ok {
		return os.ErrNotExist
	}
	delete(m.files, path)
	return nil
}
func (m *memFS) Stat(path string) (os.FileInfo, error) {
	if _, ok := m.files[path]; !ok {
		return nil, os.ErrNotExist
	}
	return nil, nil
}

func newFakeLaunchd() *launchdtest.Fake { return launchdtest.New(agent.Label) }

func newInstaller(ld *launchdtest.Fake, fs *memFS) *Installer {
	return &Installer{
		Launchctl: launchd.Client{Runner: ld, Domain: "gui/501"},
		FS:        fs,
		PlistDir:  "/Users/me/Library/LaunchAgents",
		Sleep:     func(time.Duration) {},
	}
}

const exe = "/usr/local/bin/ssh-key-control"

const (
	appExe       = "/Applications/SSH Key Control.app/Contents/MacOS/ssh-key-control"
	companionExe = "/Applications/SSH Key Control.app/Contents/MacOS/ssh-key-control-menubar"
)

func TestInstall(t *testing.T) {
	ld := newFakeLaunchd()
	ld.StartsIn = 2
	ld.JobExports = true
	fs := newMemFS()
	inst := newInstaller(ld, fs)
	res, err := inst.Install(context.Background(), exe, agent.RequireForce)
	if err != nil {
		t.Fatal(err)
	}
	wantPath := "/Users/me/Library/LaunchAgents/io.github.alvnukov.ssh-key-control.plist"
	if res.PlistPath != wantPath || res.Socket != ld.Socket || res.PID != 4242 || !res.Exported {
		t.Errorf("result = %+v", res)
	}
	data := string(fs.files[wantPath])
	for _, want := range []string{"<string>" + exe + "</string>", "<string>agent</string>", "<key>SSH_ASKPASS_REQUIRE</key>", "<string>force</string>", "SecureSocketWithKey"} {
		if !strings.Contains(data, want) {
			t.Errorf("plist lacks %q:\n%s", want, data)
		}
	}
	joined := strings.Join(ld.Calls, "\n")
	if !strings.Contains(joined, "bootout gui/501/io.github.alvnukov.ssh-key-control\nbootstrap gui/501 "+wantPath) {
		t.Errorf("calls:\n%s", joined)
	}
}

func TestInstallFromApplicationSupervisesMenuBarWithoutDuplicateStartupMechanism(t *testing.T) {
	ld := newFakeLaunchd()
	ld.JobExports = true
	fs := newMemFS()
	fs.files[companionExe] = []byte("executable")
	inst := newInstaller(ld, fs)
	res, err := inst.Install(context.Background(), appExe, agent.RequireForce)
	if err != nil {
		t.Fatal(err)
	}
	if !res.CompanionManaged {
		t.Fatal("application install did not enable menu bar supervision")
	}
	if !strings.Contains(strings.Join(ld.Calls, "\n"), "print gui/501/"+CompanionLabel) {
		t.Fatal("install reported success without observing the supervised menu process")
	}
	ld.Program = companionExe
	status, err := inst.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !status.CompanionPlistExists || status.CompanionService == nil || !status.CompanionService.Running() {
		t.Errorf("companion status is not truthful: %+v", status)
	}
	if status.CompanionExecutable != companionExe || status.CompanionExecutableAvailable == nil || !*status.CompanionExecutableAvailable {
		t.Errorf("companion executable availability = %q, %v", status.CompanionExecutable, status.CompanionExecutableAvailable)
	}
	delete(fs.files, companionExe)
	status, err = inst.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.CompanionExecutableAvailable == nil || *status.CompanionExecutableAvailable {
		t.Errorf("deleted menu executable was reported available: %v", status.CompanionExecutableAvailable)
	}
	path := inst.CompanionPlistPath()
	data := string(fs.files[path])
	for _, want := range []string{"<string>" + companionExe + "</string>", "<string>--managed</string>", "<key>SuccessfulExit</key>", "<false/>", "<key>ThrottleInterval</key>"} {
		if !strings.Contains(data, want) {
			t.Errorf("companion plist lacks %q:\n%s", want, data)
		}
	}
	joined := strings.Join(ld.Calls, "\n")
	bootout := "bootout gui/501/" + CompanionLabel
	bootstrap := "bootstrap gui/501 " + path
	if !strings.Contains(joined, bootout) || !strings.Contains(joined, bootstrap) || strings.Index(joined, bootout) > strings.Index(joined, bootstrap) {
		t.Errorf("companion lifecycle calls:\n%s", joined)
	}
	ld.Calls = nil
	if err := inst.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := ld.Calls[len(ld.Calls)-1]; got != bootout {
		t.Errorf("companion must be stopped only after agent and SSH state are restored; last call = %q\n%s", got, strings.Join(ld.Calls, "\n"))
	}
}

func TestInstallFromApplicationRequiresBundledMenuBarExecutable(t *testing.T) {
	_, err := newInstaller(newFakeLaunchd(), newMemFS()).Install(context.Background(), appExe, agent.RequireForce)
	if err == nil || !strings.Contains(err.Error(), "menu bar executable") {
		t.Fatalf("missing companion = %v", err)
	}
}

func TestInstallReplacesLoadedService(t *testing.T) {
	ld := newFakeLaunchd()
	ld.JobExports = true
	ld.Loaded[agent.Label] = "/old.plist"
	inst := newInstaller(ld, newMemFS())
	if _, err := inst.Install(context.Background(), exe, agent.RequirePrefer); err != nil {
		t.Fatal(err)
	}
	if ld.Loaded[agent.Label] != inst.PlistPath() {
		t.Errorf("loaded from %q", ld.Loaded[agent.Label])
	}
}

func TestInstallReportsMissingExport(t *testing.T) {
	ld := newFakeLaunchd()
	inst := newInstaller(ld, newMemFS())
	res, err := inst.Install(context.Background(), exe, agent.RequireForce)
	if err != nil {
		t.Fatal(err)
	}
	if res.Exported {
		t.Error("SSH_AUTH_SOCK was never set, Exported must be false")
	}
}

func TestInstallFailures(t *testing.T) {
	ctx := context.Background()
	if _, err := newInstaller(newFakeLaunchd(), newMemFS()).Install(ctx, "relative/ssh-key-control", "force"); err == nil {
		t.Error("relative path accepted")
	}
	if _, err := newInstaller(newFakeLaunchd(), newMemFS()).Install(ctx, exe, "never"); err == nil {
		t.Error("bad require accepted")
	}

	ld := newFakeLaunchd()
	ld.Fail["bootstrap gui/501 /Users/me/Library/LaunchAgents/io.github.alvnukov.ssh-key-control.plist"] = &launchd.ExitError{Code: 5, Output: "Input/output error"}
	if _, err := newInstaller(ld, newMemFS()).Install(ctx, exe, "force"); err == nil || !strings.Contains(err.Error(), "Input/output error") {
		t.Errorf("bootstrap failure: %v", err)
	}

	ld = newFakeLaunchd()
	ld.StartsIn = 1000
	if _, err := newInstaller(ld, newMemFS()).Install(ctx, exe, "force"); err == nil || !strings.Contains(err.Error(), "did not start") {
		t.Errorf("never running: %v", err)
	}

	ld = newFakeLaunchd()
	ld.Loaded[agent.Label] = "/old.plist"
	ld.Fail["bootout gui/501/io.github.alvnukov.ssh-key-control"] = &launchd.ExitError{Code: 1, Output: "refused"}
	if _, err := newInstaller(ld, newMemFS()).Install(ctx, exe, "force"); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("bootout failure: %v", err)
	}
}

func TestUninstall(t *testing.T) {
	ld := newFakeLaunchd()
	fs := newMemFS()
	inst := newInstaller(ld, fs)
	ld.JobExports = true
	if _, err := inst.Install(context.Background(), exe, "force"); err != nil {
		t.Fatal(err)
	}
	ld.Calls = nil
	if err := inst.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := ld.Loaded[agent.Label]; ok {
		t.Error("service still loaded")
	}
	if _, ok := fs.files[inst.PlistPath()]; ok {
		t.Error("plist still there")
	}
	if _, ok := fs.files[inst.CompanionPlistPath()]; ok {
		t.Error("companion plist still there")
	}
	if _, ok := ld.Env["SSH_ASKPASS"]; ok {
		t.Error("SSH_ASKPASS still set")
	}
	if _, ok := ld.Env["SSH_ASKPASS_REQUIRE"]; ok {
		t.Error("SSH_ASKPASS_REQUIRE still set")
	}
	if ld.Env["SSH_AUTH_SOCK"] != ld.Apple {
		t.Errorf("SSH_AUTH_SOCK = %q, want Apple's %q", ld.Env["SSH_AUTH_SOCK"], ld.Apple)
	}
}

func TestUninstallWhenNothingIsInstalled(t *testing.T) {
	ld := newFakeLaunchd()
	ld.Apple = ""
	ld.Env["SSH_AUTH_SOCK"] = "/stale"
	inst := newInstaller(ld, newMemFS())
	if err := inst.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := ld.Env["SSH_AUTH_SOCK"]; ok {
		t.Error("without Apple's agent SSH_AUTH_SOCK must be unset")
	}
}

func TestUninstallCollectsErrors(t *testing.T) {
	ld := newFakeLaunchd()
	ld.Loaded[agent.Label] = "/p"
	ld.Fail["bootout gui/501/io.github.alvnukov.ssh-key-control"] = &launchd.ExitError{Code: 1, Output: "busy"}
	ld.Fail["unsetenv SSH_ASKPASS"] = errors.New("no unsetenv")
	err := newInstaller(ld, newMemFS()).Uninstall(context.Background())
	if err == nil || !strings.Contains(err.Error(), "busy") || !strings.Contains(err.Error(), "no unsetenv") {
		t.Errorf("error = %v", err)
	}
	if ld.Env["SSH_AUTH_SOCK"] != ld.Apple {
		t.Error("later steps must still run after an earlier failure")
	}
}

func TestStatus(t *testing.T) {
	ld := newFakeLaunchd()
	fs := newMemFS()
	inst := newInstaller(ld, fs)
	st, err := inst.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.PlistExists || st.Service != nil || st.Running() || st.Exported() || st.Socket() != "" {
		t.Errorf("fresh system: %+v", st)
	}
	ld.JobExports = true
	if _, err := inst.Install(context.Background(), exe, "force"); err != nil {
		t.Fatal(err)
	}
	ld.Env["SSH_ASKPASS"] = exe
	st, err = inst.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !st.PlistExists || !st.Running() || !st.Exported() || st.Socket() != ld.Socket || st.Service.PID != 4242 {
		t.Errorf("installed: %+v service %+v", st, st.Service)
	}
	if st.Session["SSH_ASKPASS"] != exe || st.Session["SSH_AUTH_SOCK"] != ld.Socket {
		t.Errorf("session = %v", st.Session)
	}
	ld.Env["SSH_AUTH_SOCK"] = "/somewhere/else"
	st, _ = inst.Status(context.Background())
	if st.Exported() {
		t.Error("a different SSH_AUTH_SOCK is not exported")
	}
}

func TestStatusPropagatesErrors(t *testing.T) {
	ld := newFakeLaunchd()
	ld.Fail["getenv SSH_AUTH_SOCK"] = errors.New("launchctl broken")
	if _, err := newInstaller(ld, newMemFS()).Status(context.Background()); err == nil {
		t.Error("expected an error")
	}
}

func TestOSFS(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b")
	var fs OSFS
	if err := fs.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "f")
	if err := fs.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Stat(p); err != nil {
		t.Fatal(err)
	}
	if err := fs.Remove(p); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Stat(p); !os.IsNotExist(err) {
		t.Errorf("after remove: %v", err)
	}
}

func TestDefaultPlistDir(t *testing.T) {
	d, err := DefaultPlistDir()
	if err != nil || !strings.HasSuffix(d, filepath.Join("Library", "LaunchAgents")) {
		t.Errorf("%q, %v", d, err)
	}
}
