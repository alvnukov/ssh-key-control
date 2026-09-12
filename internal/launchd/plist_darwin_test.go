package launchd

import (
	"bytes"
	"os/exec"
	"testing"
)

// TestMarshalPlistXPC checks the parser used by launchd without loading a job.
// plutil accepts paired boolean tags, but the XPC parser rejects them.
func TestMarshalPlistXPC(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available for XPC parser check")
	}
	data, err := (Job{
		Label:              "io.example.agent",
		ProgramArguments:   []string{"/bin/true"},
		RunAtLoad:          true,
		EnableTransactions: true,
		EnvironmentVariables: map[string]string{
			"SSH_ASKPASS_REQUIRE": "force",
		},
		SecureSocket: &SecureSocket{Name: "Listeners", Key: "SSH_KEY_CONTROL_AGENT_SOCKET"},
	}).MarshalPlist()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(python, "-c", `
import ctypes
import sys
lib = ctypes.CDLL('/usr/lib/system/libxpc.dylib')
parse = lib.xpc_create_from_plist
parse.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
parse.restype = ctypes.c_void_p
lib.xpc_release.argtypes = [ctypes.c_void_p]
data = sys.stdin.buffer.read()
buf = ctypes.create_string_buffer(data)
obj = parse(buf, len(data))
if not obj:
    sys.exit('XPC rejected generated plist')
lib.xpc_release(obj)
`)
	cmd.Stdin = bytes.NewReader(data)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("XPC plist parser: %v\n%s", err, out)
	}
}
