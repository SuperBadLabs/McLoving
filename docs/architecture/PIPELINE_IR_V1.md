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
          program: cargo
          args: [test, --locked]
          env:
            CI: "true"
          timeout_seconds: 600
```

Stages are sequential. Stage IDs are unique restricted identifiers. The only
v1 step is a direct process with a program, optional string arguments, optional
string environment mapping, and optional non-negative timeout.

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

## Verification contract

- Negative fixtures cover every prohibited YAML feature.
- Property tests exercise arbitrary input panic freedom, deterministic
  admission, bounded collection expansion, and unknown-field rejection.
- Two presentation-distinct YAML documents must produce identical canonical
  bytes and semantic digests.
- Programmatically constructed IR must pass the independent structural
  validator before canonicalization.
- Mutated, truncated, non-canonical, or trailing canonical bytes are rejected.
