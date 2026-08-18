use mcloving_pipeline_ir::{
    AmbiguityPolicy, ConnectorEffectClass, ErrorCode, IR_V1_2, IR_V1_3, JsonFieldType, ParseLimits,
    ProcessMode, Step, YamlValue, compile_strict_yaml, parse_strict,
};

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

const CONNECTOR_PIPELINE: &str = r#"
version: 1
name: notify
stages:
  - id: notify
    name: Notify
    steps:
      - connector_intent:
          mapping_id: notification.v1
          mapping_digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          effect_class: externally_idempotent
          effect_key_template: build.notification
          public_input_schema:
            message: string
          protected_secret_ref_schema:
            token: string
          expected_public_result_schema:
            delivery_id: string
          timeout_seconds: 30
          ambiguity_policy: observe_then_reconcile
          downstream_control_digest: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
"#;

#[test]
fn admits_typed_connector_intent_without_authority_fields() {
    let pipeline = compile_strict_yaml(
        "fixture://connector-intent",
        CONNECTOR_PIPELINE,
        ParseLimits::default(),
    )
    .expect("compile connector intent");
    assert_eq!(pipeline.schema, IR_V1_3);
    let Step::ConnectorIntent(intent) = &pipeline.stages[0].steps[0] else {
        panic!("expected connector intent");
    };
    assert_eq!(
        intent.effect_class,
        ConnectorEffectClass::ExternallyIdempotent
    );
    assert_eq!(
        intent.ambiguity_policy,
        AmbiguityPolicy::ObserveThenReconcile
    );
    assert_eq!(intent.public_input_schema["message"], JsonFieldType::String);
    validate_no_authority_material(&pipeline.canonical_bytes().unwrap());
}

#[test]
fn connector_intent_rejects_endpoint_and_credential_overrides() {
    for forbidden in [
        "          endpoint_url: https://destination.invalid\n",
        "          credential: bearer-secret\n",
        "          program: /bin/sh\n",
    ] {
        let source = CONNECTOR_PIPELINE.replace(
            "          timeout_seconds: 30\n",
            &format!("{forbidden}          timeout_seconds: 30\n"),
        );
        let error = compile_strict_yaml(
            "fixture://connector-authority",
            &source,
            ParseLimits::default(),
        )
        .unwrap_err();
        assert!(error.message.contains("unknown field"));
    }
}

#[test]
fn connector_intent_rejects_multi_step_stage_until_sequencing_is_implemented() {
    let source = CONNECTOR_PIPELINE.replace(
        "      - connector_intent:\n",
        "      - process:\n          program: printf\n          args: [before]\n      - connector_intent:\n",
    );
    let error = compile_strict_yaml(
        "fixture://connector-multi-step",
        &source,
        ParseLimits::default(),
    )
    .unwrap_err();
    assert_eq!(error.path.as_deref(), Some("$.stages[0].steps"));
    assert!(error.message.contains("exactly one connector intent"));
}

#[test]
fn connector_intent_rejects_non_string_protected_references() {
    let source =
        CONNECTOR_PIPELINE.replace("            token: string", "            token: object");
    let error = compile_strict_yaml(
        "fixture://connector-protected-reference-type",
        &source,
        ParseLimits::default(),
    )
    .unwrap_err();
    assert_eq!(
        error.path.as_deref(),
        Some("$.stages[0].steps[0].connector_intent.protected_secret_ref_schema.token")
    );
    assert!(error.message.contains("opaque strings"));
}

fn validate_no_authority_material(bytes: &[u8]) {
    let text = String::from_utf8_lossy(bytes);
    for forbidden in ["https://", "bearer-secret", "/bin/sh"] {
        assert!(!text.contains(forbidden));
    }
}

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
fn directives_after_a_utf8_bom_are_rejected_at_the_percent_sign() {
    let error = parse_strict(
        "\u{feff}%YAML 1.2\n---\nname: rejected\n",
        ParseLimits::default(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::Directive);
    assert_eq!(error.span.start.offset, 3);
    assert_eq!(error.span.start.column, 1);
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
fn compiles_explicit_process_modes_without_shell_inference() {
    let source = r#"
version: 1
name: windows-modes
stages:
  - id: execute
    name: Execute
    steps:
      - process:
          mode: direct
          program: tool.exe
      - process:
          mode: windows_cmd
          program: command.cmd
      - process:
          mode: powershell
          program: command.ps1
"#;
    let pipeline = compile_strict_yaml("fixture://windows-modes", source, ParseLimits::default())
        .expect("compile explicit Windows modes");
    assert_eq!(pipeline.schema, IR_V1_2);
    let modes = pipeline.stages[0]
        .steps
        .iter()
        .map(|step| match step {
            Step::Process(process) => process.mode,
            Step::ConnectorIntent(_) => panic!("fixture contains only process steps"),
        })
        .collect::<Vec<_>>();
    assert_eq!(
        modes,
        vec![
            ProcessMode::Direct,
            ProcessMode::WindowsCmd,
            ProcessMode::PowerShell
        ]
    );
}

#[test]
fn rejects_unknown_process_mode_fail_closed() {
    let source = VALID_PIPELINE.replace(
        "          program: cargo",
        "          mode: shell\n          program: cargo",
    );
    let error = compile_strict_yaml("fixture://unknown-mode", &source, ParseLimits::default())
        .expect_err("unknown process mode must fail closed");
    assert_eq!(
        error.path.as_deref(),
        Some("$.stages[0].steps[0].process.mode")
    );
    assert!(error.message.contains("direct, windows_cmd, or powershell"));
}

#[test]
fn accepts_an_explicit_positive_sign_for_decimal_integers() {
    let source = VALID_PIPELINE.replace("version: 1", "version: +1");
    let pipeline =
        compile_strict_yaml("fixture://positive", &source, ParseLimits::default()).unwrap();
    assert_eq!(pipeline.name, "checkout");
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
        (
            include_str!("fixtures/invalid/complex-key.yaml"),
            ErrorCode::ComplexKey,
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

    let error = parse_strict(
        "values: [one, two, three]\n",
        ParseLimits {
            max_nodes: 3,
            ..ParseLimits::default()
        },
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::NodeLimit);
}

#[test]
fn percent_at_the_start_of_block_scalar_content_is_not_a_directive() {
    let parsed = parse_strict("|\n  %not-a-directive\n", ParseLimits::default()).unwrap();
    assert_eq!(
        parsed.value,
        YamlValue::String("%not-a-directive\n".to_owned())
    );

    let parsed = parse_strict("\"first\n%second\"\n", ParseLimits::default()).unwrap();
    let YamlValue::String(value) = parsed.value else {
        panic!("expected string");
    };
    assert!(value.contains("%second"));
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

#[test]
fn schema_type_errors_retain_the_offending_value_span() {
    for source in [
        "version: 1\nname: invalid\nstages: wrong\n",
        "version: 1\nname: invalid\nstages:\n  - id: stage\n    name: Stage\n    steps: wrong\n",
    ] {
        let error =
            compile_strict_yaml("fixture://type", source, ParseLimits::default()).unwrap_err();
        let span = error.span.expect("type error must have a source span");
        assert!(span.end.offset > span.start.offset);
    }
}
