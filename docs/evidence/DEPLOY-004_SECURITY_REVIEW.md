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

Nine scenarios were run against four library baselines: this branch,
`origin/main` at `96ef05f` (the shipping vulnerability), and both earlier
attempts at this fix — `9cda125` (exempted every sticky directory) and `f457fcc`
(scoped that exemption by a lexical home-prefix test). Each scenario builds a
fixture, calls `require_secure_ancestors`, and checks **both** the verdict and
that a refusal **names its own offender**. That second half is not decoration:
several fixtures refuse on the unpatched library for a completely unrelated
reason (`/tmp (mode 1777)`, or an opaque `cannot statx`), and a gate that only
asserted "it failed" would have recorded those as passes.

| Scenario | expected | this branch | origin/main 96ef05f | 9cda125 (attempt 1) | f457fcc (attempt 2) |
|---|---|---|---|---|---|
| `baseline-accept` | accept | accept | accept | accept | accept |
| `sticky-traversal-accept` | accept | accept | accept | accept | accept |
| `above-home-writable` | refuse | **refuse (named)** | accept | **refuse (named)** | **refuse (named)** |
| `a-managed-root-sticky` | refuse | **refuse (named)** | **refuse (named)** | accept | **refuse (named)** |
| `b-two-link-home` | refuse | **refuse (named)** | refuse, wrong reason | accept | **refuse (named)** |
| `c-foreign-link-inode` | refuse | **refuse (named)** | refuse, wrong reason | refuse, wrong reason | refuse, wrong reason |
| `d-dotdot-after-symlink` | refuse | **refuse (named)** | accept | accept | accept |
| `e-sibling-root-under-sticky` | refuse | **refuse (named)** | refuse, wrong reason | accept | accept |
| `foreign-home` | refuse | **refuse (named)** | accept | refuse, wrong reason | refuse, wrong reason |

Every scenario is red on at least one baseline, and this branch is the only
column in which every refusal names what is wrong with the host. The same nine
fixtures are carried as gates in `deploy/test-deployment.sh`, together with a
tenth that asserts the chain's own content — that `/` is present, that the
directory above the home is present and classified `traversal`, and that the
home is classified `guarded` — because an acceptance proves nothing if the walk
reached nothing. Seven of the ten go red against `96ef05f`. The full suite was
run twice end to end and passed both times, in 336 s on the second run. The five P1
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
