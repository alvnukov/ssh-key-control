package launchd

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

type systemAgentRunner struct {
	disabled, loaded bool
	failAction       string
	failCode         int
	calls            []string
}

func (r *systemAgentRunner) Run(_ context.Context, args ...string) (string, error) {
	r.calls = append(r.calls, strings.Join(args, " "))
	if args[0] == r.failAction {
		return "", &ExitError{Args: args, Code: r.failCode}
	}
	switch args[0] {
	case "print-disabled":
		return fmt.Sprintf("disabled services = {\n\t\"com.openssh.ssh-agent\" => %t\n}\n", r.disabled), nil
	case "print":
		if !r.loaded {
			return "", &ExitError{Code: 113}
		}
		return args[1] + " = {\n state = running\n pid = 123\n}\n", nil
	case "disable":
		r.disabled = true
	case "enable":
		r.disabled = false
	case "bootout":
		r.loaded = false
	case "bootstrap":
		r.loaded = true
	default:
		return "", fmt.Errorf("unexpected command %v", args)
	}
	return "", nil
}

func TestSystemAgentDisableAndRestore(t *testing.T) {
	r := &systemAgentRunner{loaded: true}
	c := Client{Runner: r, Domain: "gui/501"}
	state, err := c.SetSystemAgentDisabled(context.Background(), true)
	if err != nil || !state.Disabled || state.Loaded || state.Running || state.RequiresLogout {
		t.Fatalf("disable: %+v, %v", state, err)
	}
	state, err = c.SetSystemAgentDisabled(context.Background(), false)
	if err != nil || state.Disabled || !state.Loaded || !state.Running || state.RequiresLogout {
		t.Fatalf("restore: %+v, %v", state, err)
	}
	if !strings.Contains(strings.Join(r.calls, "\n"), "bootstrap gui/501 "+systemAgentPlist) {
		t.Fatal("did not restore system service")
	}
}

func TestSystemAgentSIPRefusalIsPendingNotDisabled(t *testing.T) {
	r := &systemAgentRunner{loaded: true, failAction: "bootout", failCode: 150}
	c := Client{Runner: r, Domain: "gui/501"}
	state, err := c.SetSystemAgentDisabled(context.Background(), true)
	if err != nil || !state.Disabled || !state.Loaded || !state.Running || !state.RequiresLogout {
		t.Fatalf("SIP: %+v, %v", state, err)
	}
	for _, call := range r.calls {
		if strings.HasPrefix(call, "kill ") || strings.HasPrefix(call, "enable ") {
			t.Fatalf("unexpected workaround: %s", call)
		}
	}
	// Model the next login: the disabled job has not been loaded.
	r.loaded = false
	state, err = c.SystemAgentStatus(context.Background())
	if err != nil || !state.Disabled || state.Loaded || state.RequiresLogout {
		t.Fatalf("next login: %+v, %v", state, err)
	}
}

func TestSystemAgentFailureDoesNotClaimSuccess(t *testing.T) {
	for _, action := range []string{"disable", "bootout"} {
		t.Run(action, func(t *testing.T) {
			r := &systemAgentRunner{loaded: true, failAction: action, failCode: 5}
			c := Client{Runner: r, Domain: "gui/501"}
			if state, err := c.SetSystemAgentDisabled(context.Background(), true); err == nil || state != nil {
				t.Fatalf("ignored failure: %+v, %v", state, err)
			}
			if action == "disable" && strings.Contains(strings.Join(r.calls, "\n"), "bootout ") {
				t.Fatal("stopped job without disabling startup")
			}
		})
	}
}

func TestSystemAgentRestoreSIPNeedsLogout(t *testing.T) {
	r := &systemAgentRunner{disabled: true, failAction: "bootstrap", failCode: 150}
	c := Client{Runner: r, Domain: "gui/501"}
	state, err := c.SetSystemAgentDisabled(context.Background(), false)
	if err != nil || state.Disabled || state.Loaded || !state.RequiresLogout {
		t.Fatalf("restore: %+v, %v", state, err)
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
