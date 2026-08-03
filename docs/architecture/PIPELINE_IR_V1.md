# Pipeline admission and IR v1 contract

Status: Wave 0 contract

## Authoring boundary

McLoving accepts a deliberately restricted YAML 1.2 language. YAML is an
authoring syntax only; it is not the durable or executable representation.

The admission parser:

- accepts exactly one non-empty document;
- preserves scanner-native byte offsets, lines, and columns for every value;
- rejects duplicate mapping keys, aliases, anchors, explicit tags, directives,
  complex keys, and implicit empty scalars;
- accepts only lowercase `null`, `true`, and `false` as non-string plain
  scalars and signed base-10 integers without leading zeroes;
- applies source-byte, node, depth, scalar, mapping, and sequence limits before
  schema compilation; and
- returns stable error categories and fails closed on every unknown schema
  field.

Default admission limits are:

| Dimension | Limit |
|---|---:|
| Source bytes | 262,144 |
| Parsed nodes | 4,096 |
| Nesting depth | 32 |
| Scalar bytes | 16,384 |
| Mapping entries | 256 |
| Sequence items | 1,024 |

## Pipeline schema v1

The first schema is intentionally narrow:

```yaml
version: 1
name: checkout
stages:
  - id: build
    name: Build
    steps:
      - process:
          mode: direct
          program: cargo
          args: [test, --locked]
          env:
            CI: "true"
          timeout_seconds: 600
```

Stages are sequential. Stage IDs are unique restricted identifiers. The only
v1 step is a process with an explicit creation mode, a program, optional string
arguments, optional string environment mapping, and optional non-negative
timeout. The mode defaults to `direct` for v1.0/v1.1 compatibility.

Unknown fields are errors at the pipeline, stage, step, and process levels.
Adding semantics therefore requires a versioned contract change rather than
silent interpretation.

## Canonical bytes and digest

Canonical bytes use a McLoving-owned length-prefixed binary format:

1. fixed `MCLOVING-IR\0` magic;
2. big-endian major and minor schema versions;
3. length-prefixed UTF-8 strings;
4. source-order stages and steps;
5. sorted environment keys; and
6. explicit step opcodes and optional-value markers.

The semantic SHA-256 covers those canonical bytes. YAML presentation, comments,
mapping order, source identity, and source spans do not change the semantic
digest. Exact source SHA-256, source identity, compiler identity, and locations
remain in the provenance envelope.

An independent byte validator checks the magic, bounds, UTF-8, opcodes,
environment ordering, optional markers, and complete input consumption. It
does not invoke the YAML parser or schema compiler.

## Compatibility rule

A reader accepts a produced IR when major versions match and the reader minor
version is greater than or equal to the produced minor version. A major
mismatch or newer producer minor version is rejected explicitly.

## Pipeline IR v1.2 explicit process modes

IR v1.2 adds exactly three process creation contracts: `direct`,
`windows_cmd`, and `powershell`. A non-direct mode promotes the semantic IR to
v1.2, and canonical bytes bind a closed mode opcode before the program. The
independent validator rejects unknown opcodes. Controller lowering carries the
mode into the agent execution specification without inspecting the program
name, extension, arguments, or command text.

`windows_cmd` and `powershell` are Windows-only. A non-Windows executor rejects
them rather than attempting a compatibility fallback. Direct mode preserves
the existing argv/no-shell behavior. This contract deliberately does not add a
generic shell string or implicit interpreter selection.

## Pipeline IR v1.1 parameters and expressions

IR v1.1 adds typed pipeline parameters and an intentionally small expression
language without changing the v1.0 byte encoding for pipelines that do not use
the feature. A parameter declaration has exactly one of the types `boolean`,
`integer`, or `string`, an optional type-matching default, and an optional
`secret: true` marker. Explicit invocation values are checked before any
expression is evaluated. Unknown, missing, or mismatched inputs fail admission.

Secret parameter values are invocation-only: they have no defaults, are
excluded from canonical IR, and taint every expression derived from them.
Materializing a tainted value into a process program, argument, or environment
field is rejected. Attempt-scoped credential delivery remains the separate
SEC-003 grant boundary.

An expression-backed string field is explicit rather than interpolated:

```yaml
version: 1
name: native
parameters:
  tool:
    type: string
    default: cargo
  target:
    type: string
    default: linux
stages:
  - id: test
    name: Test
    steps:
      - process:
          program:
            expression: parameters.tool
          args:
            - test
            - expression: parameters.target + "-release"
```

The only context is `parameters.<name>`. The only operations are parentheses,
unary `!`, `==`, `!=`, `&&`, `||`, and checked `+` for two integers or two
strings. There are no functions, implicit conversions, property traversal,
loops, I/O, clocks, randomness, or ambient controller/agent context.

Expression admission and evaluation independently enforce:

| Dimension | Limit |
|---|---:|
| Source bytes | 16,384 |
| AST nodes | 128 |
| AST depth | 16 |
| String bytes | 4,096 |
| Operations | 128 |

Canonical v1.1 bytes bind sorted parameter definitions, non-secret resolved
values, and canonical expression ASTs keyed by their unique sorted IR paths.
The independent byte validator rechecks type agreement, canonical ordering,
secret-value absence, AST opcodes and bounds, parameter references, and
complete input consumption without invoking YAML or the expression parser.

## Reusable component v1

Reusable components are admitted Pipeline IR templates packaged with a
version, name, typed output contract, exact dependency invocations, and source
provenance. Component identity is the SHA-256 of McLoving-owned canonical
package bytes. Those bytes bind the canonical pipeline template, input
definitions and defaults, output types, dependency order, exact dependency
digests, and typed dependency inputs. Source paths, comments, YAML mapping
order, spans, and compiler location do not affect the identity.

Every reference has exactly the form `sha256:<64 lowercase hex>`. Names,
branches, tags, `latest`, registries, network lookup, and other floating
resolution are rejected at this boundary. A catalog recomputes the complete
package digest before registration and again during expansion. It refuses a
different package under an existing digest, so changing the component body,
contract, or dependency graph is a detectable substitution.

Expansion occurs completely before scheduling:

1. resolve the exact package from the immutable catalog;
2. type-check explicit invocation inputs and re-evaluate only the stored,
   bounded expression ASTs;
3. recursively expand exact dependencies in declared order;
4. prefix concrete stage IDs with their deterministic invocation ordinal; and
5. emit a concrete v1.0 scheduling pipeline plus an ordered component receipt
   ledger.

The expansion canonical digest binds the root digest, every invocation path,
package digest and version, typed public inputs, declared output types, and
the concrete scheduling pipeline. Source SHA-256 remains in the provenance
receipt but is excluded from semantic bytes, just like pipeline provenance.
Two distinct component
identities therefore cannot collapse to one expansion digest even if their
current concrete steps happen to be identical.

Default expansion limits are independently enforced before scheduling:

| Dimension | Limit |
|---|---:|
| Recursive depth | 8 |
| Component invocations | 128 |
| Expanded stages | 128 |
| Expanded steps | 4,096 |
| Expansion canonical bytes | 262,144 |

Active-path cycles, missing packages, digest mismatches, zero limits, secret
component inputs, type mismatches, and every limit violation fail closed with
stable error codes. Component secrets remain attempt-scoped credential grants;
they are never component parameters or expansion-receipt values.

## Verification contract

- Negative fixtures cover every prohibited YAML feature.
- Property tests exercise arbitrary input panic freedom, deterministic
  admission, bounded collection expansion, and unknown-field rejection.
- Two presentation-distinct YAML documents must produce identical canonical
  bytes and semantic digests.
- Programmatically constructed IR must pass the independent structural
  validator before canonicalization.
- Mutated, truncated, non-canonical, or trailing canonical bytes are rejected.
- Arbitrary expression text must remain panic-free; parse and evaluation
  budgets are independent.
- Secret marker values must be absent from canonical bytes and diagnostics.
