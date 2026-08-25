# Deployment trust boundary v1 (DEPLOY-003)

Status: decided, pending implementation
Date: 2026-08-25
Applies to: the `DEPLOY-001` deployment lane — `deploy/bin/`, `deploy/systemd/`,
`deploy/podman/`, `deploy/env/`, and `deploy/test-deployment.sh`
Supersedes: nothing. Establishes the boundary that lane was built without.

This record answers a question the deployment lane was implemented without ever
stating: **who is the adversary, what may they do, and what does the lane
guarantee against them?** Every one of the 162 review findings on PR #84 was
argued case by case against an implicit model. This document writes the model
down, decides the trust boundary, and determines the fate of each obligation the
lane currently discharges.

It is a decision record, not a plan of record for code. The implementation it
authorises is tracked as `DEPLOY-003` on the execution board.

---

## 1. Why this record exists

`DEPLOY-001` merged across PR #84 and PR #93. Measured from the GitHub API
rather than from recollection:

| | measured |
|---|---|
| Top-level review findings | **162** |
| Reviewer submissions, one per head commit | **81** |
| Findings per round | **2.0**, flat |
| Severity | 62 P1, 100 P2 |
| Commits on the branch | 105 |
| Findings per day | **37, 39, 43, 43** |

Every finding was valid. None was a false positive. The daily rate **never
declined** across four days — the last two were the most productive. That is not
a curve approaching zero, and no quantity of further rounds was going to reach
it. For contrast, PR #93 — the follow-up carrying #84's deferred findings — ran
2, 2, 1, 1, 1, **0**. That is what convergence looks like.

**134 of the 162 findings (83%) landed in four scripts**
(`mcloving-deploy-lib.sh` 64, `mcloving-deployed-digests` 30,
`mcloving-env-guard` 21, `mcloving-install` 19). The units, quadlets, contracts
and the suite itself account for eight findings between them. Defect density
follows the *validation* code, not the deployment configuration it validates.

The lane's own runbook already concedes the reason
(`docs/operations/DEPLOYMENT_V1.md`):

> **Release integrity is bound to install-time identity, not tamper-proof.**
> [...] It is not a defence against a compromised service user, who owns those
> files and can rewrite them.

So the surface's stated guarantee is against corruption, partial writes, and
accidental substitution — while its complexity resembles a defence against a
hostile writer. Resolving that mismatch is what this record does.

---

## 2. The threat model

### 2.1 Adversary A — another local user. This lane's adversary.

*Identity.* A uid on the deployment host that is neither the service account nor
root, holding no deployment authority.

*Capabilities.* Exactly what Unix DAC grants: read anything world- or
group-readable — every installed unit (0644), every helper (0755), and
`/proc/PID/cmdline` of the service processes (which is why a contract is never
re-supplied on a command line); write any directory carrying group or other
write for them; create files in such a directory **including after validation
completes**; rename or replace any subtree whose parent they can write; run
processes as themselves and consume host resources.

*What they cannot do.* Write inside a directory they lack write permission on;
place a file in a root-owned system unit load path; influence the service
account's environment; become the service account.

*Assets.* What the next service start executes (release binaries, helpers,
interpreters resolved by name, units, merged drop-ins, `Exec*` arguments); what
the services trust (CA bundles, certificates, identity bindings); the secrets in
the four 0600 contracts and the mTLS private key; durable state; and the
availability of the transition itself.

*What the lane guarantees against adversary A.* **One property:**

> Every path a deployment transition or service start will read or execute is,
> at validation time, unwritable by any uid other than root or the service
> account, along its entire resolved ancestor chain to `/`; and every path that
> does not yet exist sits in a directory carrying that same property, so it
> cannot be created either. Where the property cannot be established, the
> transition refuses; it never proceeds on an unproven path.

Every gate in the lane is a case of that one sentence. Stating it once is the
substantive change this record makes — it was previously derived, separately, in
dozens of places.

*What the lane does NOT guarantee against adversary A.*

1. **No TOCTOU-freeness.** The lane cannot hold the filesystem still. It
   converts each check into a containing-directory bound. If the bound holds the
   race is unwinnable, but the guarantee is the bound, not the instant of the check.
2. **Confidentiality of anything but the secret class.** Units, helpers, release
   identity and the deployment layout are world-readable by design.
3. **Safety it can only refuse, not create.** A contract may legitimately name a
   path outside the home; the lane walks its chain and refuses if that chain is
   writable. It cannot make it safe.
4. **Resource bounds and host configuration.** The lane can decline to install
   onto a bad host; it cannot repair one.

### 2.2 Adversary B — a submitted workload running AS the service account

**This is `SEC-005`'s adversary, not this lane's.** It is stated here because
several PR #84 findings blur the line, and the blur is what makes a root-owned
deployment tree look more attractive than it is.

Adversary B owns everything adversary A cannot touch: every 0700 directory,
every 0600 contract, the mTLS private key, the release and helper trees.
`UMask=` and `StateDirectoryMode=` are irrelevant to B by construction — they are
discretionary controls against *other* users, and B is this user.

**Scope rule, applied throughout this record:** a change justified by "a
compromised service account could…" is doing `SEC-005`'s work. A change
justified by "another local user could…" is in scope here.

### 2.3 The decisive measurement about adversary A

**Under a sound ancestor chain, adversary A can write nothing.** Every managed
root is created 0700 or `go-w`; `require_secure_ancestors` refuses any chain
component that is group- or world-writable *or* owned by a third uid; the walk is
re-run inside the transition lock and again at every service start; and
non-existent paths take a creation bound on their containing directory. On a
stock host all sixteen entries of the manager's own `UnitPath` are root-owned
0755 or inside the user's own tree.

**Therefore the validation surface detects a misconfigured host; it does not
stop an attacker who already has a foothold.** That is a genuine and worthwhile
obligation — and a much cheaper one than the surface currently reflects.

---

## 3. The trust-boundary decision

**Decision: the service account continues to own its deployed tree. Status quo,
taken deliberately, with its cost stated.**

- **Who owns the deployed tree:** the unprivileged service account.
- **Who may transition it:** that same account, under an exclusive transition lock.
- **What the operator is trusted for:** the host's directory configuration —
  that no third party holds write on any ancestor of the deployment roots or of
  the manager's unit load path. The lane verifies this and refuses otherwise;
  it does not establish it.
- **What the lane is trusted for:** establishing the §2.1 invariant before every
  transition and at every service start, and refusing when it cannot.
- **What is explicitly NOT claimed:** any bound on adversary B. That is `SEC-005`.

### Why not a root-owned tree (design-doc option A)

Rejected on measurement, for three independent reasons, any one of which is sufficient:

1. **It does not reach the largest finding class.** Mapping the evidence onto
   the obligations: rounds 29–41 — the thirteen consecutive rounds that never
   converged — are O1, O2, O3, O7 and O8, which concern *which unit file systemd
   selects across sixteen load paths* and *how the environment composes*.
   Fifteen of those sixteen load paths are outside the deployment tree and
   already root-owned. A root-owned deployment root retires **none** of them.
2. **Its benefit against this lane's adversary is zero**, because (§2.3)
   adversary A can already write nothing. Its benefit is against adversary B,
   which is `SEC-005`'s ticket and `SEC-005`'s chosen mechanism.
3. **It buys new attack surface to retire old validation.** Upgrade and rollback
   rewrite the tree, so under option A they must run as root — requiring a
   privileged installer, a privilege-dropping transition script, and a new
   privileged argument parser.

Two mechanism notes, so this is not re-litigated: a separate installer account
still needs root (only root can give ownership away), and `chattr +i` needs
`CAP_LINUX_IMMUTABLE`, measured absent, and would block the installer too.

---

## 4. What the service manager can and cannot enforce — measured

Design-doc option B is "push enforcement into systemd rather than bespoke
pre-checks", and its own §9 requires this to be measured rather than assumed.
Measured on systemd 255 under `systemctl --user`, uid 1000:

**13 directives enforced. 11 silently unenforced with the unit still starting.
3 fail closed.**

| | directives |
|---|---|
| **Enforced** | `NoNewPrivileges`, `PrivateUsers`, `RestrictAddressFamilies`, `SystemCallFilter`, `RestrictNamespaces`, `LockPersonality`, `MemoryDenyWriteExecute`, `MemoryMax`, `TasksMax`, `CPUQuota`, `LimitNOFILE`, `CPUAffinity`, `UnsetEnvironment` |
| **Silently unenforced** | `ProtectSystem`, `ProtectHome`, `ReadOnlyPaths`, `InaccessiblePaths`, `BindReadOnlyPaths`, `PrivateTmp`, `PrivateNetwork`, `ProtectKernelTunables`, `ProtectControlGroups`, `ProtectProc`, `IPAddressDeny`, `IOReadBandwidthMax`, `AllowedCPUs` |
| **Fail closed (honest)** | `TemporaryFileSystem=` (226/NAMESPACE), `PrivateDevices=`, empty `CapabilityBoundingSet=` (218) |

### 4.1 Why, and why it is dangerous

systemd's executor does fork `(sd-userns)`, but Ubuntu's AppArmor
`unprivileged_userns` profile denies `CAP_SYS_ADMIN` to it, so
`unshare(CLONE_NEWNS)` returns `EPERM`. systemd then logs — **at debug level
only** — `Failed to set up namespace, assuming containerized execution and
ignoring`, starts the unit, and reports success.

Observed consequences: `ProtectHome=tmpfs` left `$HOME` fully readable, 84
entries including `.ssh/authorized_keys`. A `ReadOnlyPaths=` target was
**overwritten**. A unit declaring `ProtectSystem=strict ProtectHome=yes
ReadOnlyPaths=$HOME PrivateTmp=yes` wrote to `$HOME`, exited 0, and reported the
host's own mount-namespace inode. `systemctl --user show -p ProtectHome`
returned empty — the property was not even recorded.

**For a project whose Working rules are fail-closed throughout, a control that
fails open and reports success is worse than no control**, because it reads as a
mitigation in review.

### 4.2 The tool that is not an oracle

`systemd-analyze --user security` reported `✓ ProtectSystem=` and
`✓ PrivateTmp=` for a run in which neither was enforced. It scores declared
configuration, not achieved state.

This project already learned the identical lesson from the identical tool:
`systemd-analyze --user unit-paths` is not authoritative because it recomputes
from the *caller's* environment, and `systemctl --user show -p UnitPath` is the
manager's own answer. **That is twice, from one tool, in one class.** Hence:

> **Standing rule.** `systemd-analyze` answers from configuration and from the
> caller's environment. It is a linting tool, not an oracle. Every property this
> lane depends on is either asked of the running manager (`systemctl --user show
> -p …`, `/proc/PID/environ`) or proved by an adverse probe that attempts the
> forbidden thing. A `✓` from `systemd-analyze` is not evidence.

### 4.3 What survives, and the standing requirement

Available under the user manager: seccomp properties, rlimits, `NoNewPrivileges`,
and the cgroup bounds whose controllers are delegated. **Delegated controllers
are `cpu memory pids` only** — `io`, `cpuset`, hugetlb, rdma and misc are not, so
every IO-bandwidth and cpuset bound is a no-op rootless.

> **Standing rule.** Any hardening directive adopted for this lane ships with a
> runtime proof that it is in effect. The model exists in this repository:
> `require_shadow_apparmor_enforcement()` reads `/proc/self/attr/current` and
> refuses to load authority unless the label is exactly the expected profile.

**The shipped units are clean today.** They declare only `UnsetEnvironment=`,
`Environment=PATH=`, `StateDirectoryMode=0700`, `UMask=0077` and
`NoNewPrivileges=yes` — every one of which works. This was evidently earned
empirically across the review; it is recorded here so the next person to
"harden" these units does not walk into the trap.

**Not measured, and required before any claim that this is recoverable:**
whether `kernel.apparmor_restrict_unprivileged_userns=0`, or a targeted AppArmor
profile on `/usr/lib/systemd/systemd-executor` granting `userns,`, restores
namespacing. The kernel audit names `systemd-executor` — **not** the service
binary — so a profile on a McLoving binary would not help. `bwrap` does create
both namespaces unprivileged on this host, because it ships a profile containing
`userns,`; that is the existence proof, not a measurement of the fix.

---

## 5. The obligation determinations

The lane currently discharges eight obligations on every transition. Attributed
surface in `deploy/bin/mcloving-deploy-lib.sh` (4,199 lines; 4,036 attributed,
163 blank separators) and gates in `deploy/test-deployment.sh` (600 named
refusals in 230 blocks, of which 49 are not obligation work):

| | obligation | lines | gates | determination |
|---|---|---:|---:|---|
| **O1** | which unit file systemd would load | 917 | 99 | **Ask + union-validate.** Precedence ceases to be load-bearing. |
| **O2** | drop-in enumeration | 161 | 33 | **Ask.** `show -p DropInPaths` is the whole answer. |
| **O3** | systemd's assignment grammar | 163 | 18 | **Ask.** `show -p Exec*`/`EnvironmentFiles` return post-parse values. |
| **O4** | path-bearing directives + ancestor chains | 378 | 82 | **Retained.** Glob is un-askable; the chain walk is inherently the lane's. |
| **O5** | `Exec*` executables and arguments | 193 | 28 | **Ask.** Same properties as O3. |
| **O6** | contracts, keys, CAs, state, binaries | 776 | 182 | **Retained.** Not a systemd question. |
| **O7** | effective environment, both directions | 605 | 67 | **Already asked.** Fix the PID-recycling bound. |
| **O8** | pre-`main()` hook strip / refuse | 341 | 42 | **Split.** Strip half enforced by systemd; refuse half retained. |

O1+O2+O3+O5 — the four obligations that are purely "predict what systemd will do
with this file" — total **1,434 lines and 178 gates.**

### 5.1 Ask the manager: O2, O3, O5 (517 lines, 79 gates)

Round 34's principle was applied to O1, O7 and O8 **and nowhere else**. The
design document calls option C "already partially implemented"; the partition is
sharper than that. Measured:

- **`show -p DropInPaths` reports the exact merged drop-in file list** — the
  type-wide, dash-truncated and exact forms, across load paths, in merge order.
  That is O2's entire answer in one property. The lane queries it **nowhere**
  and re-derives all 161 lines in shell.
- **`show -p ExecStart*`, `-p EnvironmentFiles`, `-p WorkingDirectory` report
  systemd's own post-parse values**: the `-` and `@` prefixes decoded, `"a b"`
  unquoted to one token, `\x2e` unescaped to `.`, `%h` expanded. Every one of
  the five constructs `require_parseable_unit_sources` refuses by name is
  resolved in that output.

The lane refuses those five spellings precisely so it does not have to model
them. The manager will simply report them.

### 5.2 Validate the union, do not resolve the selection: O1

The lane must currently answer *which unit file systemd **will** load*, which
demands bit-exact fidelity to systemd's resolution model — and is unsound in
both directions, because selecting the wrong effective unit means validating a
file systemd will never read while the one it loads goes unchecked.

But the security property is *could an adversary have written **any** file
systemd might load?* — and that question **does not involve precedence at all**.
Over-approximation is sound: validating a candidate systemd will never load
costs a little time and loses nothing.

Measured cost of validating the whole union: **16 load paths, 43 nodes including
full ancestor chains and resolved symlink targets, 2.6 ms** — of which 2.4 ms is
the single IPC round-trip to ask the manager for `UnitPath`. Candidate
enumeration for all three units across every drop-in form is 208 paths in 0.3 ms.

This retires two of the project's hard-won systemd facts as **irrelevant** rather
than merely known: "`XDG_*` set-but-empty means an empty list" and "`XDG_DATA_DIRS`
replacement re-adds systemd's vendor tail, so membership looks unchanged while
order moves". Both matter only to a lane that ranks load paths. A lane that
validates their union cannot be wrong about the ranking.

O1's 917 lines remain available as the fallback for when the manager does not
serve the target home, but they stop being the security-critical path.

*Reproducing the measurement.* Ask the manager for its own list, then judge every
node on it — through symlinks, since a symlink's own mode bits are always `0777`
and mean nothing:

    systemctl --user show -p UnitPath --value

then for each entry, and for every ancestor to `/` plus every resolved symlink
target and that target's own ancestors, require the node to be unwritable by
group and other and owned by root or the service account. 16 entries expand to
43 distinct nodes on a stock host.

A first draft of that probe judged nodes with `lstat()` and reported
`/etc/xdg/systemd/user` as world-writable — a P1-shaped finding, since drop-ins
are *merged* from every load path rather than selected between. It is a symlink
to root-owned `/etc/systemd/user`, and the finding was false. Forty lines of
deliberately careful validation code, written directly from this review's own
history, reproduced one of its finding classes on the first attempt. The lane
itself already gets this right — `require_secure_ancestors` uses `stat -Lc` and
says why. **That is this record's thesis demonstrated rather than argued: the
validation is error-prone because the problem is, not because the implementers
were careless — which is the argument for having less of it, not for reviewing
it harder.**

### 5.3 Retained, with reasons

- **O4 (378 lines, 82 gates)** — retained. `EnvironmentFiles=` reports a wildcard
  **literally**, so glob expansion is genuinely un-askable; and the ancestor-chain
  walk is the lane's own invariant (§2.1), not a systemd question. Neither
  elimination nor enforcement is available: the filesystem directives that would
  enforce it are precisely the ones measured silently unenforced (§4).
- **O6 (776 lines, 182 gates — 30% of the suite)** — retained in full. Artifact
  identity is not a systemd question and no manager property answers it. Note it
  is the **largest** obligation and was **not** the non-converging class; its
  findings declined across the review while the systemd-modelling class rose.
- **O8 refuse half** — retained. `require_declared_variables_allowed` and
  `require_unit_environment_allowed` are validation-time default-deny rules that
  stop a bad contract from existing. They cannot be asked, and the strip half
  (`UnsetEnvironment=`, measured working) does not subsume them.

### 5.4 Defects and risks found while auditing, to be carried into implementation

1. **The lane asks for the mask answer and discards it.**
   `deployment_manager_unit_answer` parses `LoadState`/`UnitFileState`/
   `FragmentPath`, but `deployment_effective_unit_file` uses only `fragment` and
   then re-derives masking via `readlink == /dev/null` — and that *derived*
   verdict is what refuses the transition. Root cause 3.1 surviving **inside**
   the ask path.
2. **`ExecMainPID` → `/proc/PID/environ` has no bound against PID recycling.**
   Eleven other check-then-use windows carry a stated bound; this one does not.
3. **The suite specifies the model, not the ask.** Every ask is gated on the
   manager's `HOME` equalling the target home, and the suite installs into
   `mktemp -d` trees — so **20 of 600 gates (3.3%)** exercise a real manager
   query, each behind a skip-with-notice guard. Acceptance criterion 5 leans on
   the suite as the lane's specification; on this evidence it currently specifies
   the fallback. **Making the suite able to exercise the ask path is the first
   implementation task, not an afterthought** — otherwise this record's central
   recommendation lands untested.
4. **Three of eight hybrid sites label their derived answer.** The design
   document's claim that a derived fallback "must be labelled as derived, which
   the lane now does" holds for three. Unlabelled:
   `deployment_effective_cache_root`, `deployment_effective_data_root` (which
   feeds the O1 load-path derivation), the quadlet branch of
   `deployment_effective_unit_file`, and `require_unit_hook_stripping` — whose
   fallback has *different semantics*, not an approximation.
5. **`mcloving-install` runs `require_deployment_integrity` before acquiring the
   transition lock**, where upgrade and rollback run it inside. The install
   verdict is taken outside mutual exclusion. `mcloving-env-guard` re-walks
   ancestors at every `ExecStartPre` holding no lock at all.
6. **`NoNewPrivileges=yes` is absent from `mcloving-db-init.service`** and both
   quadlets, while present on the agent and controller. Probably deliberate for
   a oneshot running `podman exec`, but it is the only uncommented asymmetry in
   a lane that comments everything.

---

## 6. Relationship to `SEC-005`

The two tickets must not specify two mechanisms for one property.

- **`SEC-005` owns** containment of adversary B: the write and read allowlists,
  the pid-targeting rule, same-user IPC, ambient authority, network
  reachability, and per-workload resource bounds. Its chosen substrate —
  AppArmor entered in the agent executor — is correct and is now measured
  correct, since the systemd directives that would be the alternative are
  silently unenforced under a user manager.
- **`DEPLOY-003` owns** the lane's own boundary against adversary A, and the
  lane's own query path to the service manager.

Two seams, recorded so neither ticket assumes the other:

1. **The containment domain must be entered at step spawn, not at unit level.**
   The `ExecStart=/usr/bin/aa-exec -p …` pattern the existing profiles use would
   make the *agent* inherit the workload's denials and break this lane's ability
   to query the manager at all.
2. **`SEC-005`'s pid/`/proc` rule must bind the workload's containment domain,
   not the service identity.** A user-wide `hidepid`, `ProtectProc=` or
   `ptrace_scope` change would satisfy `SEC-005`'s letter while destroying this
   lane's O7 mechanism, which reads `/proc/ExecMainPID/environ`.

Also noted for `SEC-005` rather than acted on here: per-attempt cgroups need
`Delegate=` on `mcloving-agent.service` — a unit directive, hence this lane's —
and `io` is not a delegated controller, so disk-bandwidth and IOPS bounds are
undeliverable rootless without a root-side change. `SEC-005`'s existing
per-platform ineligibility escape already covers that case.

---

## 7. Residual risk

- The operator is trusted for the host's directory configuration. The lane
  refuses a bad host; it cannot repair one.
- No TOCTOU-freeness. The guarantee is the containing-directory bound.
- The deployment layout, units, helpers and release identity are world-readable
  by design; only the secret class is confidential.
- **Nothing here bounds adversary B.** Until `SEC-005` ships, the right to submit
  a pipeline equals the right to read this host's deployment credentials.
- Namespace-based enforcement is unavailable on Ubuntu 24.04+ hosts at default
  settings, and its absence is indistinguishable from its presence without an
  adverse probe.
