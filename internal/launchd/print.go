package launchd

import (
	"errors"
	"path"
	"strconv"
	"strings"
)

// Service is what `launchctl print` reports about a loaded service.
type Service struct {
	// Name is the full service name, for example "gui/501/com.openssh.ssh-agent".
	Name string
	// Label is the last component of Name.
	Label string
	// Path is the plist the service was loaded from.
	Path string
	// State is "running", "waiting", "not running" and the like.
	State string
	// PID is the running process, 0 when there is none.
	PID int
	// Arguments is the program and its arguments.
	Arguments []string
	// Environment is what the plist's EnvironmentVariables set.
	Environment map[string]string
	// InheritedEnvironment is what the service gets from the domain, including
	// the variables launchd derives from its sockets.
	InheritedEnvironment map[string]string
	// Sockets maps the names under the plist's Sockets key to the sockets launchd created.
	Sockets map[string]Socket
	// LastExitCode is the raw text launchctl prints, "" when the service never ran.
	LastExitCode string
}

// Socket is a listening socket launchd holds for a service.
type Socket struct {
	Path string
	// SecureKey is the environment variable launchd stores Path under.
	SecureKey string
}

// Running reports whether launchd has a process for the service.
func (s *Service) Running() bool {
	return s.State == "running" && s.PID > 0
}

// node is one `name = { ... }` block of launchctl's output.
type node struct {
	props    map[string]string // "key = value"
	env      map[string]string // "KEY => value"
	items    []string          // bare lines, such as the entries of "arguments"
	children map[string]*node
}

func newNode() *node {
	return &node{props: map[string]string{}, env: map[string]string{}, children: map[string]*node{}}
}

// parseTree reads launchctl's indented brace syntax into nested nodes.
func parseTree(text string) *node {
	root := newNode()
	stack := []*node{root}
	top := func() *node { return stack[len(stack)-1] }
	for line := range strings.SplitSeq(text, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case t == "":
		case t == "}":
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		case strings.HasSuffix(t, "= {"):
			name := strings.Trim(strings.TrimSpace(strings.TrimSuffix(t, "= {")), `"`)
			child := newNode()
			top().children[name] = child
			stack = append(stack, child)
		default:
			if k, v, ok := strings.Cut(t, " => "); ok {
				top().env[k] = v
			} else if k, v, ok := strings.Cut(t, " = "); ok {
				top().props[k] = v
			} else {
				top().items = append(top().items, t)
			}
		}
	}
	return root
}

// ParsePrint reads the output of `launchctl print <domain>/<label>`.
func ParsePrint(text string) (*Service, error) {
	root := parseTree(text)
	if len(root.children) != 1 {
		return nil, errors.New("launchctl print: unrecognised output")
	}
	svc := &Service{
		Environment:          map[string]string{},
		InheritedEnvironment: map[string]string{},
		Sockets:              map[string]Socket{},
	}
	for name, n := range root.children {
		svc.Name = name
		svc.Label = path.Base(name)
		svc.Path = n.props["path"]
		svc.State = n.props["state"]
		svc.PID, _ = strconv.Atoi(n.props["pid"])
		svc.LastExitCode = n.props["last exit code"]
		if args := n.children["arguments"]; args != nil {
			svc.Arguments = append([]string(nil), args.items...)
		}
		if env := n.children["environment"]; env != nil {
			svc.Environment = env.env
		}
		if env := n.children["inherited environment"]; env != nil {
			svc.InheritedEnvironment = env.env
		}
		if socks := n.children["sockets"]; socks != nil {
			for sockName, sock := range socks.children {
				svc.Sockets[sockName] = Socket{Path: sock.props["path"], SecureKey: sock.props["secure key"]}
			}
		}
	}
	return svc, nil
}
