use mcloving_pipeline_ir::{ErrorCode, ParseLimits, YamlValue, compile_strict_yaml, parse_strict};

const VALID_PIPELINE: &str = r#"
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
"#;

#[test]
fn parses_restricted_yaml_with_exact_key_span() {
    let parsed = parse_strict("name: build\n", ParseLimits::default()).unwrap();
    let YamlValue::Mapping(entries) = parsed.value else {
        panic!("expected mapping");
    };
    assert_eq!(entries[0].key, "name");
    assert_eq!(entries[0].key_span.start.line, 1);
    assert_eq!(entries[0].key_span.start.column, 0);
    assert_eq!(entries[0].key_span.start.offset, 0);
    assert_eq!(entries[0].key_span.end.offset, 4);
}

#[test]
fn spans_preserve_utf8_byte_offsets_and_scanner_columns() {
    let parsed = parse_strict("é: value\n", ParseLimits::default()).unwrap();
    let YamlValue::Mapping(entries) = parsed.value else {
        panic!("expected mapping");
    };
    assert_eq!(entries[0].key, "é");
    assert_eq!(entries[0].key_span.start.offset, 0);
    assert_eq!(entries[0].key_span.end.offset, 2);
    assert_eq!(entries[0].key_span.start.column, 0);
    assert_eq!(entries[0].key_span.end.column, 1);
}

#[test]
fn directive_spans_account_for_crlf_bytes() {
    let error = parse_strict(
        "\r\n%YAML 1.2\r\n---\r\nname: rejected\r\n",
        ParseLimits::default(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::Directive);
    assert_eq!(error.span.start.offset, 2);
    assert_eq!(error.span.start.line, 2);
}

#[test]
fn compiles_the_v1_process_contract() {
    let pipeline =
        compile_strict_yaml("fixture://valid", VALID_PIPELINE, ParseLimits::default()).unwrap();
    assert_eq!(pipeline.name, "checkout");
    assert_eq!(pipeline.stages.len(), 1);
    assert_eq!(pipeline.stages[0].steps.len(), 1);
    assert_eq!(pipeline.provenance.source_id, "fixture://valid");
}

#[test]
fn rejects_negative_corpus_with_stable_codes() {
    let cases = [
        (
            include_str!("fixtures/invalid/duplicate-key.yaml"),
            ErrorCode::DuplicateKey,
        ),
        (
            include_str!("fixtures/invalid/alias.yaml"),
            ErrorCode::Alias,
        ),
        (
            include_str!("fixtures/invalid/anchor.yaml"),
            ErrorCode::Anchor,
        ),
        (include_str!("fixtures/invalid/tag.yaml"), ErrorCode::Tag),
        (
            include_str!("fixtures/invalid/directive.yaml"),
            ErrorCode::Directive,
        ),
        (
            include_str!("fixtures/invalid/multiple-documents.yaml"),
            ErrorCode::MultipleDocuments,
        ),
        (
            include_str!("fixtures/invalid/empty-value.yaml"),
            ErrorCode::EmptyScalar,
        ),
    ];

    for (source, expected) in cases {
        let error = parse_strict(source, ParseLimits::default()).unwrap_err();
        assert_eq!(error.code, expected, "source was {source:?}");
    }
}

#[test]
fn enforces_all_collection_and_scalar_limits() {
    let error = parse_strict(
        "root:\n  nested:\n    value: accepted\n",
        ParseLimits {
            max_depth: 2,
            ..ParseLimits::default()
        },
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::DepthLimit);

    let error = parse_strict(
        "values: [one, two]\n",
        ParseLimits {
            max_sequence_items: 1,
            ..ParseLimits::default()
        },
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::SequenceLimit);

    let error = parse_strict(
        "one: 1\ntwo: 2\n",
        ParseLimits {
            max_mapping_entries: 1,
            ..ParseLimits::default()
        },
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::MappingLimit);

    let error = parse_strict(
        "value: oversized\n",
        ParseLimits {
            max_scalar_bytes: 4,
            ..ParseLimits::default()
        },
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::ScalarLimit);
}

#[test]
fn unknown_fields_fail_closed_at_every_schema_level() {
    for source in [
        VALID_PIPELINE.replace("name: checkout", "name: checkout\nmystery: true"),
        VALID_PIPELINE.replace("    name: Build", "    name: Build\n    mystery: true"),
        VALID_PIPELINE.replace(
            "          program: cargo",
            "          program: cargo\n          mystery: true",
        ),
    ] {
        let error =
            compile_strict_yaml("fixture://unknown", &source, ParseLimits::default()).unwrap_err();
        assert!(
            error.message.contains("unknown field"),
            "unexpected error: {error}"
        );
        assert!(error.span.is_some());
    }
}
