# DEPLOY-004 security and implementation closure

`DEPLOY-004` closes a live vulnerability on `main`: the deployment lane
validated nothing above the deployment home, and every ownership rule in the
library derived its expected uid from `stat` of the home. A home whose parent
another local user could write was therefore substitutable, and the substituted
home became its **own trust anchor** — the rules measured the attacker's tree
against the attacker's uid and agreed with themselves.

**Severity: credential compromise, not merely arbitrary execution.** An
attacker-authored unit with an arbitrary `ExecStart` passed
`require_integrity_files` — the one rule whose own comment promises to stop
exactly that — and the user manager then ran it **as** the service account. From
there the original renamed-aside home's 0600 contracts and mTLS private key are
readable, because they are owned by precisely that uid. `require_secret_files
"${EUID}"` is a check the lane performs on itself, not a sandbox: code already
executing as the service account is not subject to it, and a hostile unit simply
omits it.

**Exposure is layout-dependent and overclaiming it would be its own defect.** A
stock `/home` install under a root-owned 0755 parent was never exposed.
Shared-group deploy roots, `chmod 777` container volume roots, and `--home` into
a scratch tree were — which is exactly the set of layouts someone relocating a
service home chooses.

## What was measured, and against what

Twelve scenarios were run against five library baselines: this branch,
`origin/main` at `96ef05f` (the shipping vulnerability), both earlier attempts at
this fix — `9cda125` (exempted every sticky directory) and `f457fcc` (scoped that
exemption by a lexical home-prefix test) — and **this branch's own pre-review
state**, which is in the table because it had a hole of its own and the gates
that catch it exist only because review found it. Each scenario builds a
fixture, calls `require_secure_ancestors`, and checks **both** the verdict and
that a refusal **names its own offender**. That second half is not decoration:
**six of the twelve refuse on `96ef05f` for a wholly unrelated reason** — five
naming a 1777 directory (`/tmp` or `/var/tmp`), one dying on an opaque
`stat: cannot statx ... Permission denied` — and three more are outright
accepted. A gate that only asserted "it failed" would have recorded those six as
passes.

| Scenario | expected | this branch | origin/main 96ef05f | 9cda125 (attempt 1) | f457fcc (attempt 2) | this branch, pre-review |
|---|---|---|---|---|---|---|
| `baseline-accept` | accept | accept | accept | accept | accept | accept |
| `sticky-traversal-accept` | accept | accept | accept | accept | accept | accept |
| `above-home-writable` | refuse | **refuse (named)** | accept | **refuse (named)** | **refuse (named)** | **refuse (named)** |
| `a-managed-root-sticky` | refuse | **refuse (named)** | **refuse (named)** | accept | **refuse (named)** | **refuse (named)** |
| `b-two-link-home` | refuse | **refuse (named)** | refuse, wrong reason | accept | **refuse (named)** | **refuse (named)** |
| `c-foreign-link-inode` | refuse | **refuse (named)** | refuse, wrong reason | refuse, wrong reason | refuse, wrong reason | **refuse (named)** |
| `d-dotdot-after-symlink` | refuse | **refuse (named)** | accept | accept | accept | **refuse (named)** |
| `e-sibling-root-under-sticky` | refuse | **refuse (named)** | refuse, wrong reason | accept | accept | **refuse (named)** |
| `sticky-single-absent-child` | refuse | **refuse (named)** | refuse, wrong reason | accept | refuse, wrong reason | accept |
| `sticky-last-child-absent` | refuse | **refuse (named)** | refuse, wrong reason | accept | accept | accept |
| `host-vartmp-squat` | refuse | **refuse (named)** | refuse, wrong reason | accept | refuse, wrong reason | accept |
| `foreign-home` | refuse | **refuse (named)** | accept | refuse, wrong reason | refuse, wrong reason | **refuse (named)** |

Every scenario is red on at least one baseline, and this branch is the only
column in which every refusal names what is wrong with the host.

**Twelve gates in `deploy/test-deployment.sh`** carry ten of these twelve
fixtures, plus one that asserts the chain's own content — that `/` is
present, that the directory above the home is present and classified
`traversal`, and that the home is classified `guarded` — because an acceptance
proves nothing if the walk reached nothing, and one that requires the digest
inventory to move when only an ancestor symlink's inode changes hands. Two
fixtures are deliberately not
gates: `sticky-last-child-absent` is the same defect as the sibling-root gate in
a different spelling and is covered by that gate's fixture being renamed so its
absent entry sorts last, and `host-vartmp-squat` exercises the host's real
`/var/tmp`, which a suite must not depend on the state of.

The full suite was run end to end six times and passed each time — twice before
review, and once after each of the three rounds of change that followed — at
336 s on a measured run, consistent with the
~302 s the previous custodian recorded.

`scripts/validate-foundation.sh` was **not** run here: every check it performs is
covered by a CI job that passed on this branch, except `actionlint`, which no CI
job runs. `actionlint` was therefore run directly against
`.github/workflows/*.yml` and is clean. Saying which of the two happened matters
more than claiming the script ran. The five P1
findings that stopped the earlier attempts map onto rows 4–8; the two
acceptance rows are what prove the walk to `/` has not made ordinary
deployments refuse.

**Three of those five findings were left unverified by the previous author**,
who recorded that he could not construct a foreign-owned symlink inode as uid
1000 in the time available. All three are now reproduced. `podman unshare
setpriv --reuid=1` produces a genuinely foreign inode on this host, and the two
that need no foreign uid at all — `..` after a symlink, and the sibling root
under a shared sticky ancestor — were **accepted by both earlier attempts**.

**The trust-anchor inversion shows up directly in the table.** On `f457fcc`,
`foreign-home` refuses — but it refuses the wrong directory, reporting
`expected uid 100000` for an ancestor this account owns. The attacker's home had
already supplied the uid every later comparison was made against.

## What review found, and what it says about the evidence

Two independent reviewers were run over the finished diff, one instructed to
break the check and one instructed to find where it refuses CORRECT work. **They
independently found the same real bypass**, and it was mine.

The sticky exemption's child scan was written as
`while read ... done < <(printf '%s' "${children}" | tr ',' '\n')`. `printf '%s'`
emits no trailing newline, so `read` returns non-zero on the final unterminated
field and the loop body never runs for it. Where a sticky ancestor has **exactly
one** walked entry — which is the ordinary case, and is the shape of every
deployment under `/tmp` — that discarded every child, and the exemption
collapsed to "the child list is non-empty". Reproduced against the host's real
`/var/tmp`: a home plus a single not-yet-created managed root under `1777 root`
was **accepted**.

Three things failed at once, and the third is the one worth carrying:

1. The pipeline dropped the last element. An ordinary shell bug.
2. The guard I had added *specifically* to make an empty child list fail closed —
   `[[ -n "${children}" ]] && exempt=1` — is what made the degenerate case look
   handled. A fail-closed check written one line above the hole made the hole
   invisible.
3. **The evidence matrix was green for a reason unrelated to correctness.** The
   sibling-root fixture used an absent root named `external-units` and a present
   one named `svc-home`; children are emitted sorted, `e` sorts before `s`, so
   the checked child was the absent one and the dropped child was the present
   one. Rename the absent root to sort last and the identical hostile tree is
   accepted. The verdict depended on a filename.

That third point is this ticket's own lesson turned back on itself. The whole
method here was "a refusal is not evidence until you know what it refused" — and
the acceptance direction needed the same scepticism, which it did not get. The
child scan now splits in the shell (`IFS=',' read -r -a`), with no pipeline and
no last element to lose; the sibling-root fixture is renamed so its absent entry
sorts last; and a further gate covers the degenerate one-child case directly.
The `this branch, pre-review` column above is that hole, left in the record.

### Round 2 — the inventory was blind to something the walk refuses

The repository's review bot raised a P2 that my adversarial reviewer had seen and
judged acceptable, and the bot was right. `require_secure_ancestors` treats a
symlink component's own inode owner as security-relevant, but the classified
chain's `link` records were being dropped from the deployed-digests inventory
entirely. Measured: `podman unshare chown -h 1:1` on an ancestor symlink left the
canonical document **byte-identical** while the very next transition refused the
deployment by name.

That is the project's defining failure in its exact shape — **a freeze reporting
no drift about a fact that has already invalidated the deployment**. The two
reviewers split on it because they were asking different questions: repointing a
link does move the document (the resolved ancestor paths change), so it looked
covered; changing only the *entry's owner* moves nothing, and that is the case
the ownership rule exists for.

A symlink component now carries its own record — path, `lstat` uid and gid, and
its target — read twice around the `lstat` and refused if it moved. No mode (a
symlink's is 0777 and unsettable), no digest, no timestamps: the same
record-what-you-assert rule the traversal records follow. A gate installs into a
home whose `.local` is a symlink, hands only the inode to a foreign uid, requires
the document to move, hands it back, and requires the document to return.

### Round 3 — the record I had just added had the same shape of hole

The bot's next finding was against the fix for its previous one, and it was also
right. `link_record` witnessed stability by reading the target text twice around
the `lstat`. A symlink replaced atomically by another symlink with the **same
target text** but a different owner leaves both `readlink` calls agreeing while
the pathname now names a different entry — so the record would have emitted the
removed inode's uid and let the freeze miss exactly the ownership drift the
record was added to expose.

The witness is now the **inode and the ownership**, not the target text:
`(st_dev, st_ino, st_uid, st_gid)` compared across the read, retried, and
reported as `unstable_entry` if it will not hold still. A replacement gets a new
inode; an in-place `chown` keeps the inode and moves the uid; both are caught.

Measured end to end: an atomic same-target replacement to a foreign uid changes
`st_ino` (7494292 → 7494295) with the target text unchanged, and the document
moves. Stated honestly, the *interleaving* the bot describes — a replacement
landing between the `lstat` and the second `readlink` — is a two-syscall window I
did not construct deterministically; what is demonstrated is the mechanism the
fix rests on, which is that the inode changes and the target text does not.

**Twice in this review the same shape recurred: a check whose witness was the
wrong fact.** The child scan witnessed "the list is non-empty" instead of "every
child is sound"; this one witnessed "the target text is unchanged" instead of
"this is still the same entry". Both were written by me, one immediately after
being taught the lesson by the other.

**The refusal's remedy text was also wrong, and that was the other reviewer's
top finding.** The message ended "run chmod go-w (or restore ownership) on them
and retry", which was right while every offender it could name was inside the
deployment. It can now name `/`, `/tmp` and `/var/tmp`, where `chmod go-w` is
between useless and destructive, and two of the four clauses are not about mode
bits at all. The remedy is now stated per clause, and when the lane is invoked
as root — where `expected uid 0 or root` reads as a tautology — the refusal says
that the invoking account is the problem and that chowning the tree to root
would undo `DEPLOY-003`'s decision.

## What changed

- **The walk reaches `/`**, for the home's own chain as well as for every
  managed root. The home used to be held aside as a *stop value* and was the one
  path the component walk never traversed.
- **Resolution is component by component in filesystem order.** `..` is consumed
  only after the prefix ahead of it has been resolved, because `link/..` is the
  parent of the link's *target*. `os.path.abspath` and `os.path.normpath` both
  collapse it lexically first, which walked a decoy tree while the kernel used
  another one.
- **The directory holding each intermediate symlink joins the chain**, and each
  symlink's own inode is judged by `lstat` rather than through its target.
- **Every chain node arrives classified** — `guarded` for the home, a managed
  root, or anything at or below one; `traversal` for a strict ancestor; `link`
  for a symlink component. The chain's transport carries the classification, so
  the refusal walk and the digest inventory cannot disagree about it.
- **The sticky exemption is scoped by that classification.** A `traversal`
  directory may be group- or world-writable only when it carries `S_ISVTX`
  **and** every entry this walk enters inside it already exists and is owned by
  root or the service account. `S_ISVTX` restricts renaming and unlinking other
  people's entries; it does **not** restrict creating one, and drop-ins are
  merged — so a managed root at 1777, or a sibling root sharing a sticky
  ancestor with the home, is one previously absent `.conf` away from arbitrary
  execution. Ownership is never excused, for anything.
- **The expected uid is `${EUID}`**, in `require_secure_ancestors`,
  `require_secure_files` and `require_integrity_files`. That is the pin
  `require_secret_files` has always used, and it is the uid the user manager
  runs these units as.

## Determinism, which this fix would otherwise have broken

Reaching above the home pulls shared directories — `/tmp`, `/` — into the digest
inventory's `ancestors` section, and `mcloving-deployed-digests` promises a
byte-identical document across two invocations so a `CUTOVER-001` freeze is
verifiable. **Two mechanisms break, and fixing only the first is insufficient**;
the previous attempt made exactly that mistake and its author recorded it: "I
moved the non-determinism rather than removing it."

1. `entries_sha256` hashes a directory's sorted entry basenames, which differ
   between two reads of `/tmp` seconds apart.
2. The **common final recheck** compares `S_IMODE`, `uid`, `gid`, `size`,
   `mtime_ns` and `ctime_ns` between the open-time `fstat` and a later `stat`.
   A directory's size, mtime and ctime all move when any unrelated process
   creates or unlinks an entry inside it, so sustained churn exhausts all three
   attempts and the record degrades to `kind: unstable_entry` — which fails the
   freeze exactly as loudly as a hash disagreement.

A `traversal` ancestor is therefore recorded by mode, uid and gid alone, with
size, mtime and ctime excluded from both the record and the retry decision. The
`(dev, ino)` identity check and the symlink-target check are kept: those are
substitution signals, not volatility.

This is deliberately keyed on the chain's classification and **not** on the
existing "outside the deployment root" test. They are different questions: an
external managed root such as `/etc/systemd/user` is outside the deployment root
and its contents are exactly what the lane cares about.

## One measured correction to the finding record

The foreign-owned-symlink finding was raised as full substitution. On any host
with `fs.protected_symlinks=1` — the Linux default, and the setting on the
machine this was measured on — the kernel refuses to *follow* a foreign-owned
symlink inside a world-writable sticky directory with `EACCES`, before any of
the lane's rules run. The practical effect on a stock host is therefore denial of
service rather than substitution.

The `lstat` ownership rule is kept anyway, for two reasons that are worth
separating: `fs.protected_symlinks` is a tunable that hardened and legacy
configurations do turn off, and a refusal that names the symlink and its owner is
worth more to an operator than an opaque `stat: cannot statx … Permission
denied`. The finding is real; its severity was overstated, and saying so is part
of the receipt.

## Bounded deliberately

**Two uid derivations still read `stat` of the home** —
`deployment_runtime_root` and the unit load-path derivation. They were left
alone, and this is a decision rather than an oversight: they *select where to
look* rather than deciding trust, everything they select is then judged by the
classified walk, and that walk now refuses a foreign-owned home outright, so a
substituted home cannot reach them. Changing them would also alter the
documented "a home whose owner cannot be stat-ed yields no such load path"
contract, which is a separate question from this ticket's.

**The exemption's remaining assumption is stated rather than hidden.** A sticky
traversal ancestor is trusted to the extent that `S_ISVTX` is enforced and that
the entries the walk enters inside it are owned by root or the service account
*at validation time*. This is a containing-directory bound, not TOCTOU-freeness
— the same bound the rest of the lane already carries.

**The symlink-inode rule is deliberately broader than its own justification.**
It refuses a foreign-owned `link` record anywhere in the chain, while the reason
it exists — that `S_ISVTX` grants unlink to the entry's owner — only bites where
the holding directory permits unlinking. A foreign-owned link inside a
non-writable, non-sticky directory cannot be replaced by its owner, and refusing
it buys nothing. It is kept broad because the narrow form needs the holder's mode
at the moment the link is judged, which is a second coupling to get wrong late,
and because every layout a review could construct that reaches it (a
`tar --same-owner` restore, a uid migration) leaves the *directories* wrong too
and so fails on the ownership rule regardless. Narrowing it to links whose holder
is group- or other-writable is a defensible follow-up, not a defect.

**A traversed ancestor's record is less sensitive than it was.** Chains that
already left the home walked to `/` before this change, so `/etc` and
`/etc/systemd` carried a full record including their entry hash; they are now
stable-facts-only, and a traversed ancestor swapped for a different directory
with identical mode, uid and gid produces a byte-identical record. This is the
design's own rule applied consistently — the document asserts about a directory
it merely walks through exactly what the lane checks about it — and the
`(st_dev, st_ino)` re-check still fires. An earlier revision of this receipt also
claimed a moved link no longer names itself in the document; that was true and is
no longer — see round 2 below.

**Running the lane as root is refused, and that is policy rather than an
accident.** With the anchor pinned to `${EUID}`, `sudo mcloving-install --home
<service tree>` refuses every path in a tree it does not own.
`docs/operations/DEPLOYMENT_V1.md` documents `sudo -u <account>` as the form,
and the refusal now says so rather than printing `expected uid 0 or root`. The
place this is most likely to be met is `recovery_command`, whose whole purpose
is to be pasted during an incident.

**A shared-group deploy root is refused and is not supported.** A `root:apps
2775` parent is rejected on its mode, correctly — any member of that group can
rename the deployment aside — but re-moding a directory with other tenants is
not something an installer may do on an operator's behalf. Now stated in
`docs/operations/DEPLOYMENT_V1.md` rather than left to be discovered.

## Residual risk

- **TOCTOU is unchanged.** The guarantee is the containing-directory bound, not
  the instant of the check. `mcloving-install` still takes its verdict before it
  acquires the transition lock, and `mcloving-env-guard` holds no lock at all;
  both are tracked under `DEPLOY-003`.
- **The walk is now longer on the service-start path.** `mcloving-env-guard`
  calls `require_secure_ancestors` three times at every `ExecStartPre`, and each
  call now ascends to `/`. On a host whose `/home` or `/` is group-writable or
  third-party-owned this becomes a service-start refusal rather than only an
  install refusal. That is the correct behaviour — such a host cannot protect
  the deployment — but it is a behaviour change an operator can meet at start
  time rather than at install time.
- **Nothing here bounds the service account itself.** A workload runs as that
  account and owns every contract, the mTLS private key, and the release and
  helper trees. That boundary is `SEC-005`.
