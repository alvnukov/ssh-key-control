package launchd

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
)

// NativeSocket reads only Apple's loaded service, never the shell's agent
// variable. An unexpected job definition is not a deletion target.
func (c Client) NativeSocket(ctx context.Context) (string, error) {
	service, err := c.Print(ctx, SystemAgentLabel)
	if err != nil {
		return "", err
	}
	return nativeSocket(service, c.Domain.Service(SystemAgentLabel))
}
func nativeSocket(service *Service, name string) (string, error) {
	if service == nil || service.Name != name || service.Label != SystemAgentLabel ||
		service.Path != systemAgentPlist || len(service.Arguments) != 2 ||
		service.Arguments[0] != "/usr/bin/ssh-agent" || service.Arguments[1] != "-l" {
		return "", errors.New("cannot identify Apple's SSH agent")
	}
	sock, ok := service.Sockets["Listeners"]
	if !ok || sock.SecureKey != "SSH_AUTH_SOCK" || !filepath.IsAbs(sock.Path) ||
		filepath.Clean(sock.Path) != sock.Path || filepath.Base(sock.Path) != "Listeners" {
		return "", errors.New("cannot identify Apple's SSH agent socket")
	}
	// Apple's launchd owns this namespace. Never accept ~/.ssh or a path
	// supplied by SSH_AUTH_SOCK, even if a malformed response points there.
	dir := filepath.Dir(sock.Path)
	root := filepath.Dir(dir)
	if (root != "/var/run" && root != "/private/var/run" && root != "/private/tmp" && root != "/tmp") ||
		!strings.HasPrefix(filepath.Base(dir), "com.apple.launchd.") {
		return "", errors.New("unexpected Apple SSH agent socket location")
	}
	return sock.Path, nil
}
