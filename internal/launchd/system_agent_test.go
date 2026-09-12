package launchd

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

type systemAgentRunner struct {
	disabled, loaded bool
	calls            []string
}

func (r *systemAgentRunner) Run(_ context.Context, args ...string) (string, error) {
	r.calls = append(r.calls, strings.Join(args, " "))
	switch args[0] {
	case "print-disabled":
		return fmt.Sprintf("disabled services = {\n\t\"com.openssh.ssh-agent\" => %t\n}\n", r.disabled), nil
	case "print":
		if !r.loaded {
			return "", &ExitError{Code: 113}
		}
		return args[1] + " = {\n state = running\n pid = 123\n}\n", nil
	default:
		return "", fmt.Errorf("unexpected mutation %v", args)
	}
}
func TestSystemAgentStatusIsReadOnly(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		for _, loaded := range []bool{false, true} {
			runner := &systemAgentRunner{disabled: disabled, loaded: loaded}
			client := Client{Runner: runner, Domain: "gui/501"}
			state, err := client.SystemAgentStatus(context.Background())
			if err != nil || state.Disabled != disabled || state.Loaded != loaded || state.Running != loaded {
				t.Fatalf("%+v %v", state, err)
			}
			for _, call := range runner.calls {
				if !strings.HasPrefix(call, "print") {
					t.Fatalf("mutation: %s", call)
				}
			}
		}
	}
}
func TestSystemAgentDisabledParsing(t *testing.T) {
	for _, value := range []string{"true", "disabled", "false", "enabled"} {
		got, err := systemAgentDisabled("disabled services = {\n\"com.openssh.ssh-agent\" => " + value + "\n}")
		if err != nil || got != (value == "true" || value == "disabled") {
			t.Fatalf("%s: %t, %v", value, got, err)
		}
	}
	for _, text := range []string{"", "garbage", "disabled services = {\n\"com.openssh.ssh-agent\" => perhaps\n}",
		"disabled services = {\n\"com.openssh.ssh-agent\" => true\n\"com.openssh.ssh-agent\" => false\n}"} {
		if _, err := systemAgentDisabled(text); err == nil {
			t.Fatalf("accepted %q", text)
		}
	}
}
