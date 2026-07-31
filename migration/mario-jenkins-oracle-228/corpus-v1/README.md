# Mario Jenkins oracle corpus v1

This private evidence bundle pins the exact 228 Jenkinsfiles loaded into the
owner-designated Mario `jenkins-oracle-228`. It is a migration corpus, not a
claim that McLoving can execute any source.

GitHub primary API evidence resolves every original file to an exact commit and
blob. The repository copy is byte-identical for 226 files. Six token-like
literals across the other two files are replaced by typed `secret://jenkins/`
references; `typed-redactions.tsv` binds the original source digest, repository
digest, and a protected-evidence-keyed HMAC without storing the value or key.
Original bytes remain only in the frozen Mario/protected evidence.

Repository license detection is recorded without invention: 127 repositories
have a declared SPDX license and 101 are `NOASSERTION`. The latter remain
`evidence-only-noassertion` and cannot become an admitted redistribution or
migration fixture without a separate reviewed license decision.

`SOURCE_METHOD_ORIGINAL.md` is retained unchanged as historical evidence. Its
text describes the earlier 100-file target even though the preserved source
set later grew to 228; this bundle corrects that denominator in its own
contract rather than rewriting history.

The immutable Jenkins oracle records three separate gates:

| Gate | Count |
|---|---:|
| Declarative model valid | 80 / 228 |
| Compile/CPS entry | 199 / 228 |
| Agent scheduling reached | 119 / 228 |

None is successful execution. The oracle had zero executors and the source
jobs are disabled. `source-job-map.tsv` binds the 228 files to all 230 frozen
jobs, including two controls over one source, and preserves each disabled
generation. The repaired successor inventory is byte-identical to the original
source for 226 files; `jenkins-source-normalization.tsv` proves the four CRLF
sources that Jenkins/XML 1.0 canonically stores with LF line endings. Linux and
Windows execution cases are both denied until later tickets establish mappings
and differential evidence.

The 90-plugin profile is bound by its sealed manifest SHA-256 rather than
duplicating a version lock whose `name:version` syntax produces false-positive
secret alerts.

`SCENARIO_CONTRACT.yaml` pre-registers the required behavior families and
bounded cases. Every family is currently `unsupported`; the two synthetic
secret markers may be injected only at invocation and their absence is checked
through every persisted evidence file. MIG-003 may admit a case only by adding
exact expected traces and independent Rust validation without weakening this
bundle.

Rebuild the joined views from the sealed evidence:

```sh
scripts/build-jenkins-corpus-index.py \
  migration/mario-jenkins-oracle-228/corpus-v1 \
  migration/mario-jenkins-oracle-228/inventory-20260731T064417Z-r2
```

The builder refuses to overwrite an existing index. Verify the sealed bundle:

```sh
scripts/verify-jenkins-corpus.py verify \
  migration/mario-jenkins-oracle-228/corpus-v1
```
