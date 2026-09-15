# Scoping temporary decisions to the calling process chain

## Problem Statement

When I approve a signature for fifteen minutes, I am approving far more than I
think I am.

Today a temporary decision is remembered against `{key fingerprint, host key,
user}`. Nothing in that triple says *who asked*. For the next fifteen minutes
every process running as me can sign for that destination with that key, in
silence: a build script, a browser extension's helper, a package
`postinstall`, anything. I clicked the button because I trusted the terminal I
was sitting in front of. The grant I actually made was to the whole machine.

The confirmation dialog compounds this. It tells me the key fingerprint and
the server identity, and says nothing about the program that wants the
signature. When a dialog appears that I did not expect, I have no way to tell
an editor's background fetch from something I should be alarmed about. The
honest answer to "is this me?" is usually "probably", and "probably" is a poor
basis for handing out a signing capability.

The information exists. The kernel knows exactly which process is on the other
end of the agent socket, and it knows that process's ancestry. We were simply
throwing it away.

## Solution

Every signing request is resolved to the chain of processes that produced it,
from `ssh` up to the session's root application. The chain is shown in the
confirmation dialog, and a temporary decision is remembered against *that
chain*, not against the key alone.

The dialog draws a line through the chain marking the **lease boundary**. Below
the line are the processes belonging to this one command — they will exit when
it finishes. Above the line is the durable part of the session: the shell, the
agent, the terminal application. The duration buttons apply to the process at
the boundary and say so by name, so the scope of the grant is readable on the
button being pressed.

A lease granted to `claude.exe [45430]` is usable only by descendants of that
process. A second terminal tab, a background daemon, or a script started from
a different window gets its own dialog. Ancestry is decided by the kernel at
`fork`, so it cannot be forged or borrowed.

Refusals stay broad. "Deny for 15 minutes" is a panic button, and a panic
button that only stops one process is not a panic button.

## User Stories

1. As someone approving a signature, I want to see which program asked for it, so that I can tell a routine fetch from something I did not start.
2. As someone approving a signature, I want to see the whole ancestry and not just the immediate caller, so that "ssh" and "git" — which tell me nothing — are not the only things I am shown.
3. As someone reading the dialog, I want each process shown with its pid, so that I can find it with standard tools while the dialog is still open.
4. As someone reading the dialog, I want the lease boundary drawn into the chain, so that I can see which processes the grant will outlive and which it will not.
5. As someone granting fifteen minutes, I want the button to name the process it applies to, so that the scope is on the control I press rather than in text above it.
6. As someone denying for an hour, I want the button to say the refusal covers everything, so that I am not misled by symmetry with the allow buttons.
7. As a developer running `git fetch` repeatedly from one shell, I want the second and third runs to reuse the lease, so that process scoping does not turn into a dialog for every command.
8. As a developer, I want a lease granted in one terminal tab to have no effect in another tab, so that approving in one place does not quietly arm another.
9. As a developer using an agent like Claude Code, I want the lease to attach to the agent process rather than to the shell it spawns per command, so that a lease survives more than one command.
10. As a developer working in tmux, I want the lease to attach to the pane's shell rather than to the tmux server, so that one approved pane does not arm every pane.
11. As a developer opening a brand-new tmux pane, where every process is the same age, I want the boundary still to be found, so that the feature does not silently degrade in the case with no age difference.
12. As a developer whose editor spawns `ssh` with no controlling terminal, I want the boundary still to be found, so that GUI-launched tools are anchored too.
13. As a security-conscious user, I want a lease to stop working the moment any process above the boundary exits, so that a grant cannot outlive the session it was made in.
14. As a security-conscious user, I want a recycled pid never to inherit a lease, so that a short-lived attacker cannot wait for a pid to come round again.
15. As a security-conscious user, I want a process that replaces its own image with `exec` to lose the lease, so that a lease cannot be handed to a different program.
16. As a user of a self-updating application, I want it to be anchorable even though its executable file and code signature are no longer readable, so that the feature works for the tools I actually use.
17. As a user, I want a process whose signature cannot be verified to be marked in the dialog, so that I can tell verified links from unverified ones at a glance.
18. As a user, I want verified links to show their signing identity, so that I can confirm the terminal really is the terminal.
19. As a user with a deep process tree, I want the middle of a long chain collapsed, so that the dialog stays a dialog and does not fill the screen.
20. As a user with a deep process tree, I want `ssh`, the boundary and the topmost application always visible even when the middle is collapsed, so that collapsing never hides the part I am deciding about.
21. As a user who disagrees with the computed boundary, I want to move it up the chain by clicking a link, so that I can deliberately grant to the whole terminal when that is what I mean.
22. As a user, I do not want to move the boundary down the chain, so that I cannot create a lease that is already dead when it is stored.
23. As a user, I want a duration meaning "as long as this process lives", so that I can express the bound I actually have in mind instead of guessing at minutes.
24. As a user choosing that duration, I want it capped at a day, so that an application I leave open for a fortnight does not hold a grant for a fortnight.
25. As a user running `ssh -f` or a daemon with no usable ancestry, I want the old broad behaviour to remain available, so that scripted workflows keep working.
26. As a security-conscious user, I want to turn that fallback off, so that I can require every lease to be anchored.
27. As a security-conscious user, I want turning the fallback off to be something no other program can silently undo, so that the setting is worth having.
28. As a user, I want a broad lease created by an unanchored request to apply only to other unanchored requests, so that the fallback does not become a way to arm anchored ones.
29. As a user whose request carries no verified destination, I want the existing single-signature behaviour unchanged, so that knowing the caller is not mistaken for knowing where the signature goes.
30. As a user, I want the chain rebuilt after I answer the dialog, so that a lease is never stored against a chain different from the one I was shown.
31. As a user, I want my approval still to produce the one signature I approved even when the chain changed while the dialog was open, so that answering a dialog is never wasted.
32. As a user reviewing active temporary decisions, I want each row to name the process and pid it belongs to, so that I can tell several leases apart.
33. As a user reviewing active temporary decisions, I want to see whether the anchoring process is still alive, so that a dead lease is visibly dead rather than quietly absent.
34. As a user who suspects one program, I want to revoke all of its leases at once, so that I do not have to hunt through rows during an incident.
35. As a user reading the decision journal, I want the boundary process recorded, so that I can reconstruct which program held a grant.
36. As a privacy-conscious user, I do not want my full process tree written to disk, so that the journal does not become a record of how I spend my day.
37. As a user, I want leases to disappear when the agent restarts, so that the existing promise that no approval is written to disk continues to hold.
38. As a user on a build without the platform integration, I want signing still to work, so that the feature degrades rather than breaks.
39. As a maintainer, I want chain resolution to cost microseconds, so that it is never a reason to skip it.
40. As a maintainer, I want the lease rules testable without spawning real processes, so that the security-critical logic is covered by ordinary unit tests.

## Implementation Decisions

### Chain resolution (agent package, platform side)

The peer's audit token is already obtained for attestation. It is extended to
yield the peer's `(pid, pidversion)`, and ancestors are walked upward. Each
link carries: pid, pidversion, parent pid, controlling tty, start time,
display name, and signing identity where available.

`trustedLocalSSH` becomes a special case of the new resolution rather than a
separate path; the non-platform build returns an empty chain.

Per-link identity is `(pid, pidversion)`. Prototyping established that
`pidversion` changes across `exec` (observed 122968 → 122972 for a pid that
`exec`ed), so image substitution is detected without hashing anything.

Not every link yields every field. Measured on a real chain:

```
                            path    ppid/age/tty   audit token   code signature
same uid, image on disk      ✓          ✓               ✓              ✓
same uid, image unlinked   ESRCH        ✓               ✓        errSecCSStaticCodeNotFound
root-owned (login, pid 1)    ✓        EPERM             ✗              ✗
```

Consequences, all of which the design accepts:

- A self-updating application (Claude Code is one) has no readable path and no
  obtainable code signature. Its short `comm` name is always available.
  Attestation is therefore *used when present and never required* — requiring
  it would exclude the primary use case.
- Root-owned links yield neither `pidversion` nor a start time; only the bare
  pid and `comm`. They are stored by pid alone. This is safe because the chain
  is matched whole and in ancestry order: a recycled pid can only match if it
  is genuinely an ancestor of the new `ssh` *and* genuinely the parent of the
  next stored link, and a process whose real parent died has already been
  reparented away. A weakly identified link sandwiched between strongly
  identified ones cannot be substituted.
- If the walk cannot continue past an opaque link, a boundary already found
  below that point still yields an anchor. A walk that dies before any
  boundary is found produces an unanchored request.

### Lease boundary (confirmation package)

Two candidate cuts are computed and the **lower** one wins, which always
yields the narrowest lease. From the prototype:

```
links[0] = ssh, ascending by ancestry, pid 1 excluded

ttyCut = lowest i where links[i].tty != links[0].tty     (only when links[0] has a tty)
ageCut = lowest i where links[i].age >= links[i-1].age * 10
                    and links[i].age -  links[i-1].age  >= 30s

boundary = min(ttyCut, ageCut)        # a missing cut is +infinity
anchor   = links[boundary:]           # the whole list above the cut
```

Neither signal is sufficient alone, which is why both are kept. Measured:

| scenario | tty cut | age cut | lower |
|---|---|---|---|
| iTerm + agent + shell | at the terminal app — far too broad | at the agent | agent ✓ |
| fresh tmux pane (all processes 1.1s old) | at the pane shell | none found | pane shell ✓ |
| shell spawned by an agent with no tty | not applicable | at the agent | agent ✓ |

The two conditions on `ageCut` are both required: a ratio alone fires on
infant ages (5ms → 80ms is also ×16).

### Grant key and matching (confirmation package)

`grantKey` gains the anchor: the full ordered list of links above the
boundary. A cached approval applies only when **every** stored link is still
alive and still an ancestor of the requesting `ssh`.

Refusals keep the existing chainless key. Lookup is two-stage: broad refusal
first, then anchored approval. A refusal therefore continues to stop
everything, and narrowing the approval side is a strict improvement — an
attacker who could forge a chain gains exactly what they already have today.

Unanchored requests (`ssh -f`, double-fork, non-platform builds) use the
chainless key and may hold a broad lease. That lease is matched only against
other unanchored requests.

### Authorization flow (agent and confirmation packages)

The signing request carries the raw chain. It is resolved per signature —
prototyped at ~31 µs, negligible against a dialog — and **resolved again after
the dialog closes**. This mirrors the existing post-dialog re-attestation for
local peers. If the chain changed while the dialog was open, the approved
signature is produced but no lease is stored: the user approved a signature,
not a chain they never saw.

`Authorize` owns the whole of this: it receives the raw chain, computes the
boundary, renders it, reads back a boundary the user may have moved, and forms
the key. The boundary must be recomputed after the dialog in any case, so
splitting it out would buy nothing.

### Dialog contract (ui package and macOS UI)

`ConfirmRequest` carries the ordered chain, the computed boundary index, and
per-link display data: name, pid, signing identity or a flag saying it could
not be verified.

- The chain renders in full up to twelve links; beyond that the middle
  collapses while `ssh`, the boundary and the top link stay visible.
- Links are clickable to move the boundary **upward only**.
- `Confirmation` reports the boundary index the user settled on.
- Allow buttons name the boundary process; deny buttons name the scope
  ("deny 15 minutes for all applications").
- A new grant scope means "while this process lives". Because the whole-list
  match already kills every lease when the boundary process exits, this is
  implemented as a 24-hour expiry with an honest label — no new mechanism.

### Settings

The toggle governing broad leases for unanchored requests lives **only** in
the macOS UI. The daemon never learns of it; when it is off the UI simply
omits the duration buttons for an unanchored request. A setting that cannot
reach the daemon cannot silently weaken it, and any process that flipped it
back would still need a human to press the button.

### Manager and journal

`TemporaryDecision` gains the boundary process name, its pid, and whether it
is still alive. `DecisionChange` gains a revoke-all-for-process action.

The decision journal records the boundary link only — pid, pidversion, and
path or `comm`. The rest of the chain is never written to disk.

Leases remain in memory. The existing invariant that no approval is written to
disk is unchanged.

## Testing Decisions

A good test here asserts what the user experiences: given this chain and this
answer, is the next request prompted or silent. It never reaches for the
internals of the decision store, and it never spawns a process to make a point
that a struct can make.

**Primary seam: `Authorize`.** This is the existing seam — current lease tests
already drive it with a fake scoped dialog and an injected clock — and it
absorbs all the new behaviour without a new one:

- boundary selection: tty cut, age cut, lower-of-two, and the three measured
  scenarios above as table cases
- whole-list matching: reuse when the chain is unchanged; a prompt when any
  stored link is gone; a prompt when a link's pidversion changed
- broad refusal beating an anchored approval
- unanchored requests: broad lease granted, and matched only against other
  unanchored requests
- a boundary moved upward by the user producing the broader key
- a chain that changed during the dialog producing a signature and no lease
- requests with no verified destination still prompting every time
- each grant scope's expiry, extending the existing table

**Platform seam (existing):** the darwin peer tests already assert against the
test binary's own real ancestry. They grow to cover that a chain is produced
at all, that the walk survives a root-owned link, and that a link with no
readable path still yields a name. This is the only place a real process is
required.

**Protocol seam (existing):** the UI helper tests cover the new dialog fields
across the wire and that an unparseable or out-of-range boundary index fails
closed, matching the existing fail-closed tests for scoped confirmations.

**Swift side:** existing UI test files cover scoped confirmation and temporary
decisions; chain rendering, boundary clicks and revoke-all extend them.

Localization tests already assert that both catalogues stay in step; the new
strings must be added to both.

## Out of Scope

- Persisting leases across an agent restart.
- Any per-application allowlist, or remembering a program between sessions.
  Every lease is still an explicit, time-bounded, in-memory decision.
- Narrowing refusals to a chain.
- Granting leases to requests with no verified destination.
- Requiring code signing for anchoring, or any policy keyed on team identifier
  or signing identity. Signing information is displayed, never enforced.
- Chain resolution on non-Darwin platforms.
- Any change to key storage, agent protocol handling, or session binding.

## Further Notes

Nested shells that `exec` collapse out of the chain, and a double-forked
process is reparented to pid 1 immediately and is indistinguishable from a
legitimate daemon. Both are known limits; the first is harmless (the surviving
process is still correctly identified), and the second is exactly what the
unanchored path exists to handle.

The strict whole-list match has a real cost: `exec zsh`, restarting a shell, or
closing a terminal tab kills the lease and produces a fresh dialog. This was
chosen deliberately over matching only the boundary link.

The original report that started this work — an `agent refused operation`
failure from `ssh` — is unrelated and remains uninvestigated.
