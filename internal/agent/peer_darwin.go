//go:build darwin && cgo

package agent

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <bsm/audit.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdint.h>

// The audit token comes from the kernel, never from an agent message. Its PID
// version identifies the original process even if its numeric PID is reused.
static int skc_peer_token(int fd, audit_token_t *token) {
	uid_t uid;
	gid_t gid;
	socklen_t length = sizeof(*token);
	if (getpeereid(fd, &uid, &gid) != 0 || uid != geteuid())
		return 0;
	return getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, token, &length) == 0
		&& length == sizeof(*token);
}

static int skc_number(CFDictionaryRef info, CFStringRef key, int64_t *number) {
	CFTypeRef value = CFDictionaryGetValue(info, key);
	return value && CFGetTypeID(value) == CFNumberGetTypeID()
		&& CFNumberGetValue((CFNumberRef)value, kCFNumberSInt64Type, number);
}

static int skc_trusted_ssh(const audit_token_t *token) {
	CFDataRef audit = CFDataCreate(NULL, (const UInt8 *)token, sizeof(*token));
	if (!audit) return 0;
	const void *keys[] = { kSecGuestAttributeAudit };
	const void *values[] = { audit };
	CFDictionaryRef attributes = CFDictionaryCreate(NULL, keys, values, 1,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFRelease(audit);
	if (!attributes) return 0;
	SecCodeRef code = NULL;
	OSStatus status = SecCodeCopyGuestWithAttributes(NULL, attributes,
		kSecCSDefaultFlags, &code);
	CFRelease(attributes);
	if (status != errSecSuccess) return 0;

	SecRequirementRef requirement = NULL;
	CFDictionaryRef info = NULL;
	int trusted = 0;
	status = SecRequirementCreateWithString(
		CFSTR("anchor apple and identifier \"com.apple.ssh\""),
		kSecCSDefaultFlags, &requirement);
	if (status != errSecSuccess) goto done;
	if (SecCodeCheckValidity(code, kSecCSStrictValidate, requirement) != errSecSuccess)
		goto done;
	if (SecCodeCopySigningInformation(code,
		kSecCSSigningInformation | kSecCSDynamicInformation, &info) != errSecSuccess)
		goto done;

	int64_t signature_flags = 0, dynamic_flags = 0;
	if (!skc_number(info, kSecCodeInfoFlags, &signature_flags)
		|| !skc_number(info, kSecCodeInfoStatus, &dynamic_flags))
		goto done;
	if (!(signature_flags & kSecCodeSignatureRuntime)
		|| !(dynamic_flags & kSecCodeStatusValid)
		|| (dynamic_flags & kSecCodeStatusDebugged))
		goto done;

	// Do not accept an otherwise signed executable with runtime injection
	// exceptions. A copied or renamed untrusted binary cannot satisfy the
	// Apple requirement; a trusted process must also remain dynamically valid.
	CFTypeRef entitlements = CFDictionaryGetValue(info, kSecCodeInfoEntitlementsDict);
	if (!entitlements && CFDictionaryContainsKey(info, kSecCodeInfoEntitlements))
		goto done;
	if (entitlements) {
		if (CFGetTypeID(entitlements) != CFDictionaryGetTypeID()) goto done;
		CFStringRef unsafe_keys[] = {
			CFSTR("com.apple.security.get-task-allow"),
			CFSTR("com.apple.security.cs.disable-library-validation"),
			CFSTR("com.apple.security.cs.allow-dyld-environment-variables"),
			CFSTR("com.apple.security.cs.allow-unsigned-executable-memory"),
			CFSTR("com.apple.security.cs.disable-executable-page-protection"),
			CFSTR("com.apple.security.cs.allow-jit")
		};
		for (size_t i = 0; i < sizeof(unsafe_keys) / sizeof(unsafe_keys[0]); i++) {
			CFTypeRef value = CFDictionaryGetValue((CFDictionaryRef)entitlements, unsafe_keys[i]);
			if (value && !CFEqual(value, kCFBooleanFalse)) goto done;
		}
	}
	trusted = 1;
done:
	if (info) CFRelease(info);
	if (requirement) CFRelease(requirement);
	CFRelease(code);
	return trusted;
}
*/
import "C"

import (
	"net"
	"unsafe"

	"github.com/alvnukov/ssh-key-control/internal/proc"
)

// peerToken asks the kernel who holds the other end of the socket. Everything
// this file knows about a client starts here: nothing is taken from an agent
// message, a process name, a PID on its own, or a self-reported flag.
func peerToken(conn net.Conn) (C.audit_token_t, bool) {
	var token C.audit_token_t
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return token, false
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return token, false
	}
	var captured C.int
	if err := raw.Control(func(fd uintptr) {
		captured = C.skc_peer_token(C.int(fd), &token)
	}); err != nil || captured == 0 {
		return token, false
	}
	return token, true
}

// trustedLocalSSH checks the live peer rather than trusting a process name,
// executable path, PID alone, or a client's self-reported forwarding flag.
// Failure to attest leaves ordinary publickey requests strictly one-shot.
func trustedLocalSSH(conn net.Conn) bool {
	token, ok := peerToken(conn)
	if !ok {
		return false
	}
	return C.skc_trusted_ssh(&token) != 0
}

// peerProcessChain names the client and its ancestors, so that a temporary
// decision can belong to the shell or application that asked for it instead of
// to everything running as this user. An unreadable peer yields an empty
// chain, which leaves the request unanchored rather than anchored to a guess.
func peerProcessChain(conn net.Conn) proc.Chain {
	token, ok := peerToken(conn)
	if !ok {
		return proc.Chain{}
	}
	// The token is handed on whole rather than picked apart here: reading a
	// process out of it belongs with everything else that reads processes.
	return proc.ResolveToken(C.GoBytes(unsafe.Pointer(&token), C.int(unsafe.Sizeof(token))))
}
