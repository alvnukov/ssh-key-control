package cli

import (
	"context"
	"errors"
	"log"
	"net"
	"sync"
	"time"

	"github.com/alvnukov/ssh-key-control/internal/agent"
	"github.com/alvnukov/ssh-key-control/internal/confirmation"
	"github.com/alvnukov/ssh-key-control/internal/sshconfig"
	"github.com/alvnukov/ssh-key-control/internal/ui"
	"github.com/alvnukov/ssh-key-control/internal/ui/helper"
	sshagent "golang.org/x/crypto/ssh/agent"
)

func (a *App) openTemporaryDecisions(ctx context.Context, args []string) error {
	if err := noArgs("permissions", args); err != nil {
		return err
	}
	if a.SSHConfig == "" {
		return errors.New("cannot determine the home directory")
	}
	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", (sshconfig.ManagedConfig{Path: a.SSHConfig}).SocketPath())
	if err != nil {
		return errors.New("the protected SSH agent is unavailable")
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	_, err = sshagent.NewClient(conn).Extension(agent.ManageDecisionsExtension, nil)
	return err
}

// Only the installed helper spawned here can send edits over its private pipe.
// The public agent extension has no edit/list payload; it merely opens the UI.
type temporaryDecisionManager struct {
	app            *App
	authorizer     *confirmation.Authorizer
	ctx            context.Context
	mu             sync.Mutex
	running, focus bool
}

func (m *temporaryDecisionManager) open() error {
	m.mu.Lock()
	m.focus = true
	if m.running {
		m.mu.Unlock()
		return nil
	}
	m.running = true
	m.mu.Unlock()
	fail := func(err error) error {
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
		return err
	}
	path, err := helper.LocateInstalled()
	if err != nil {
		return fail(err)
	}
	childCtx, cancel := context.WithCancel(m.ctx)
	child, err := m.app.StartHelper(childCtx, path)
	if err != nil {
		cancel()
		return fail(err)
	}
	manager, ok := child.(ui.DecisionManager)
	if !ok {
		cancel()
		_ = child.Close()
		return fail(errors.New("the installed helper does not support temporary decisions"))
	}
	go func() {
		defer func() {
			cancel()
			_ = child.Close()
			m.mu.Lock()
			m.running = false
			m.mu.Unlock()
		}()
		message := ""
		for childCtx.Err() == nil {
			m.mu.Lock()
			activate := m.focus
			m.focus = false
			m.mu.Unlock()
			change, err := manager.ManageDecisions(childCtx, m.authorizer.TemporaryDecisions(), message, activate)
			if err != nil {
				if childCtx.Err() == nil {
					log.New(m.app.Stderr, "ssh-key-control permissions: ", 0).Print(err)
				}
				return
			}
			message = ""
			switch change.Action {
			case "close":
				return
			case "refresh":
				continue
			default:
				if err := m.authorizer.ChangeTemporaryDecision(change); err != nil {
					message = err.Error()
				}
			}
		}
	}()
	return nil
}
