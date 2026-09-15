//go:build darwin && cgo

package proc

/*
#cgo LDFLAGS: -lbsm -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <mach/mach.h>
#include <sys/param.h>
#include <sys/proc_info.h>
#include <stdint.h>
#include <string.h>

typedef struct {
	int32_t  pid;
	uint32_t version;
	int32_t  ppid;
	uint32_t tty;
	int32_t  tty_known;
	int64_t  start;
	char     name[2 * MAXCOMLEN + 1];
	char     path[PROC_PIDPATHINFO_MAXSIZE];
} skc_link;

// skc_audit_token asks the kernel for a process's own audit token, which
// carries the PID version. It is refused for a process owned by another user,
// which is why a root-owned ancestor arrives without one.
static int skc_audit_token(int pid, audit_token_t *token) {
	mach_port_t task = MACH_PORT_NULL;
	if (task_name_for_pid(mach_task_self(), pid, &task) != KERN_SUCCESS)
		return 0;
	mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
	int ok = task_info(task, TASK_AUDIT_TOKEN, (task_info_t)token, &count) == KERN_SUCCESS
		&& count == TASK_AUDIT_TOKEN_COUNT
		&& audit_token_to_pid(*token) == pid;
	mach_port_deallocate(mach_task_self(), task);
	return ok;
}

// skc_link_info reports what the kernel will say about one process. Nothing is
// inferred: a field the kernel withholds is left at its zero value, and the
// caller is told which fields those are.
static int skc_link_info(int pid, skc_link *out) {
	memset(out, 0, sizeof(*out));
	out->pid = pid;
	struct proc_bsdinfo full;
	struct proc_bsdshortinfo brief;
	if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &full, sizeof(full)) == (int)sizeof(full)) {
		out->ppid = full.pbi_ppid;
		out->tty = full.e_tdev;
		out->tty_known = 1;
		out->start = (int64_t)full.pbi_start_tvsec;
		strlcpy(out->name, full.pbi_comm, sizeof(out->name));
	} else if (proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &brief, sizeof(brief)) == (int)sizeof(brief)) {
		// All another user's process will tell us: parent, name and owner.
		out->ppid = brief.pbsi_ppid;
		strlcpy(out->name, brief.pbsi_comm, sizeof(out->name));
	} else {
		return 0;
	}
	// A program that replaced its own executable has no readable path. That
	// is ordinary for a self-updating application, not a reason to distrust it.
	if (proc_pidpath(pid, out->path, sizeof(out->path)) <= 0)
		out->path[0] = '\0';
	audit_token_t token;
	if (skc_audit_token(pid, &token))
		out->version = audit_token_to_pidversion(token);
	return 1;
}

// skc_token_identity reads the process identity out of a kernel audit token,
// exactly as the kernel recorded it when the connection was made.
static int skc_token_identity(const void *bytes, size_t size, int32_t *pid, uint32_t *version) {
	audit_token_t token;
	if (size != sizeof(token))
		return 0;
	memcpy(&token, bytes, sizeof(token));
	*pid = audit_token_to_pid(token);
	*version = audit_token_to_pidversion(token);
	return 1;
}

static int skc_copy_string(CFDictionaryRef info, CFStringRef key, char *out, size_t size) {
	CFTypeRef value = CFDictionaryGetValue(info, key);
	if (!value || CFGetTypeID(value) != CFStringGetTypeID())
		return 0;
	return CFStringGetCString((CFStringRef)value, out, size, kCFStringEncodingUTF8);
}

// skc_signature reports the signing identity of a running process, and only
// when macOS confirms the running image still matches its signature. It is
// shown to the user and never required: an unsigned or unreadable process is
// displayed as such rather than excluded.
static int skc_signature(int pid, char *identifier, size_t identifier_size,
		char *team, size_t team_size) {
	audit_token_t token;
	if (!skc_audit_token(pid, &token))
		return 0;
	CFDataRef audit = CFDataCreate(NULL, (const UInt8 *)&token, sizeof(token));
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
	int described = 0;
	CFDictionaryRef info = NULL;
	if (SecCodeCheckValidity(code, kSecCSDefaultFlags, NULL) != errSecSuccess)
		goto done;
	if (SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info) != errSecSuccess)
		goto done;
	if (!skc_copy_string(info, kSecCodeInfoIdentifier, identifier, identifier_size))
		goto done;
	if (!skc_copy_string(info, kSecCodeInfoTeamIdentifier, team, team_size))
		team[0] = '\0';
	described = 1;
done:
	if (info) CFRelease(info);
	CFRelease(code);
	return described;
}
*/
import "C"

import "unsafe"

import "time"

// Resolve walks from the process identified by pid and version up through its
// ancestors. It reads only what the kernel reports, never blocks, and never
// fails: a chain it could not build is an empty one, which callers read as a
// request from nowhere in particular rather than as an error.
//
// A nonzero version is the caller's own idea of which process this is, taken
// from the kernel when the connection arrived. A process that has replaced its
// image since then is a different program and yields no chain at all.
func Resolve(pid int32, version uint32) Chain {
	var chain Chain
	seen := make(map[int32]bool, maxDepth)
	for len(chain.Links) < maxDepth {
		if pid <= 1 || seen[pid] {
			return chain
		}
		seen[pid] = true
		link, parent, ok := describe(pid)
		if !ok {
			return chain
		}
		if len(chain.Links) == 0 && version != 0 {
			if link.Version != 0 && link.Version != version {
				return Chain{}
			}
			link.Version = version
		}
		chain.Links = append(chain.Links, link)
		if parent <= 1 {
			chain.Complete = true
			return chain
		}
		pid = parent
	}
	return chain
}

// ResolveToken names the process a kernel audit token refers to, and walks up
// from there. The token is the kernel's own record of who opened a connection,
// so it is the one starting point that cannot be claimed by the caller.
func ResolveToken(token []byte) Chain {
	var pid C.int32_t
	var version C.uint32_t
	if len(token) == 0 || C.skc_token_identity(unsafe.Pointer(&token[0]), C.size_t(len(token)), &pid, &version) == 0 {
		return Chain{}
	}
	return Resolve(int32(pid), uint32(version))
}

// Alive reports whether the very same process is still running. A PID that has
// come round again belongs to someone else and is not alive for this purpose.
func Alive(l Link) bool {
	live, _, ok := describe(l.PID)
	return ok && l.Same(live)
}

// Describe adds signing identities to a chain, for showing it to the user. It
// is deliberately not part of resolving one: reading signatures costs orders
// of magnitude more than reading the process table, and no decision depends on
// the result.
func Describe(c Chain) Chain {
	links := make([]Link, len(c.Links))
	copy(links, c.Links)
	var identifier [256]C.char
	var team [64]C.char
	for i := range links {
		if C.skc_signature(C.int(links[i].PID), &identifier[0], C.size_t(len(identifier)),
			&team[0], C.size_t(len(team))) == 0 {
			continue
		}
		links[i].Identifier = C.GoString(&identifier[0])
		links[i].Team = C.GoString(&team[0])
		links[i].Verified = true
	}
	return Chain{Links: links, Complete: c.Complete}
}

func describe(pid int32) (Link, int32, bool) {
	var info C.skc_link
	if C.skc_link_info(C.int(pid), &info) == 0 {
		return Link{}, 0, false
	}
	link := Link{
		PID:      int32(info.pid),
		Version:  uint32(info.version),
		Name:     C.GoString(&info.name[0]),
		Path:     C.GoString(&info.path[0]),
		TTY:      uint32(info.tty),
		TTYKnown: info.tty_known != 0,
	}
	if info.start > 0 {
		link.Start = time.Unix(int64(info.start), 0)
	}
	return link, int32(info.ppid), true
}
