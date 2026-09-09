use super::*;
use serde_json::Value;
use std::path::Path;

fn context(source: &[u8]) -> DocumentContext {
    context_named(source, "fresh-document", "authored-document")
}
fn context_named(source: &[u8], id: &str, kind: &str) -> DocumentContext {
    let value = map(vec![
        ("document-id", text(id)),
        ("origin", text("review:independent")),
        ("origin-kind", keyword(kind)),
        ("schema", text("mcloving.jenkins.source-document/1")),
        ("source-sha256", text(&sha256_hex(source))),
    ]);
    parse_document_context(&encoded(&value), source).unwrap()
}
fn expected<'a>(source: &'a [u8], context: &'a DocumentContext) -> SequentialExpectedAdmission<'a> {
    SequentialExpectedAdmission {
        request_id: "test:sequential",
        source,
        context,
    }
}
fn program(body: &str) -> Vec<u8> {
    format!("pipeline {{ agent any; stages {{ stage('Build') {{ steps {{ {body} }} }} }} }}")
        .into_bytes()
}
fn response(source: &[u8], context: &DocumentContext) -> Edn {
    // Start only from historical authority/profile fixtures, not a worker that
    // executes source. The test constructs adversarial attributed envelopes.
    let original = super::super::parse_canonical_response(include_bytes!(
        "../../tests/fixtures/mig003-golden.edn"
    ))
    .unwrap();
    let Edn::Map(original) = original else {
        panic!()
    };
    let mut fields = vec![
        ("authority", field(&original, "authority").unwrap().clone()),
        ("compiler", text(COMPILER)),
        ("protocol", text(PROTOCOL)),
    ];
    match source::classify(source) {
        Classification::Rejected(code) => fields.extend([
            ("status", keyword("rejected")),
            (
                "diagnostic",
                map(vec![
                    ("code", text(code)),
                    (
                        "message",
                        text("request rejected without execution authority"),
                    ),
                ]),
            ),
        ]),
        classification => {
            fields.extend([
                ("contract-sha256", text(CONTRACT_SHA256)),
                ("request-id", text("test:sequential")),
                (
                    "target-profile",
                    field(&original, "profile").unwrap().clone(),
                ),
                ("source-context", context.value.clone()),
                (
                    "source",
                    map(vec![
                        ("bytes", Edn::Integer(source.len() as i64)),
                        ("context-sha256", text(&context.context_sha256())),
                        ("sha256", text(&sha256_hex(source))),
                    ]),
                ),
            ]);
            match classification {
                Classification::Supported(stages) => {
                    let yaml = pipeline_yaml(context.document_id(), &stages);
                    let digest = sha256_hex(yaml.as_bytes());
                    let definition = definition_yaml(context, &digest);
                    fields.extend([
                        ("status", keyword("compiled")),
                        (
                            "result",
                            map(vec![
                                (
                                    "agent-mapping",
                                    map(vec![
                                        ("effect-authority", Edn::Bool(false)),
                                        ("jenkins-selector", text("any")),
                                        ("mcloving-platform", text("linux")),
                                        ("trust-pool", text("migration-deny-authority")),
                                    ]),
                                ),
                                ("pipeline-yaml", text(&yaml)),
                                ("pipeline-yaml-sha256", text(&digest)),
                                ("definition-yaml", text(&definition)),
                                (
                                    "definition-yaml-sha256",
                                    text(&sha256_hex(definition.as_bytes())),
                                ),
                                (
                                    "semantic",
                                    map(vec![
                                        ("stages", Edn::Integer(stages.len() as i64)),
                                        (
                                            "steps",
                                            Edn::Integer(
                                                stages
                                                    .iter()
                                                    .map(|s| s.scripts.len())
                                                    .sum::<usize>()
                                                    as i64,
                                            ),
                                        ),
                                    ]),
                                ),
                            ]),
                        ),
                    ]);
                }
                Classification::Unsupported(code) => fields.extend([
                    ("status", keyword("unsupported")),
                    (
                        "diagnostic",
                        map(vec![
                            ("code", text(code)),
                            (
                                "message",
                                text("source is outside the currently admitted compiler subset"),
                            ),
                        ]),
                    ),
                ]),
                _ => panic!("test source has no independently classified response"),
            }
        }
    }
    map(fields)
}
fn change(value: &mut Edn, path: &[&str], replacement: Edn) {
    let Edn::Map(fields) = value else { panic!() };
    if path.len() == 1 {
        fields.insert(path[0].to_owned(), replacement);
    } else {
        change(fields.get_mut(path[0]).unwrap(), &path[1..], replacement);
    }
}

#[test]
fn protected_manifest_population_and_exact_semantics() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let bytes =
        std::fs::read(base.join("compat/jenkins-worker/fixtures/sequential-v1/manifest.json"))
            .unwrap();
    assert_eq!(
        sha256_hex(&bytes),
        "654898829f31872d471db88830414b23a9453e021bec281f05ac1aa4175de727"
    );
    let manifest: Value = serde_json::from_slice(&bytes).unwrap();
    let fixtures = manifest["fixtures"].as_array().unwrap();
    assert_eq!(fixtures.len(), 23);
    let mut supported = 0;
    let mut denied = 0;
    for fixture in fixtures {
        let id = fixture["id"].as_str().unwrap();
        let source = std::fs::read(base.join(fixture["source_path"].as_str().unwrap())).unwrap();
        assert_eq!(
            sha256_hex(&source),
            fixture["source_sha256"].as_str().unwrap(),
            "{id}"
        );
        let classification = source::classify(&source);
        match fixture["expected"]["compilation"].as_str().unwrap() {
            "supported" => {
                let Classification::Supported(stages) = &classification else {
                    panic!("{id}: {classification:?}")
                };
                let wanted = fixture["expected"]["stages"].as_array().unwrap();
                assert_eq!(stages.len(), wanted.len(), "{id}");
                for (stage, wanted) in stages.iter().zip(wanted) {
                    assert_eq!(stage.name, wanted["name"].as_str().unwrap(), "{id}");
                    let scripts: Vec<_> = wanted["steps"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|s| s["script_utf8"].as_str().unwrap())
                        .collect();
                    assert_eq!(stage.scripts, scripts, "{id}");
                }
                supported += 1;
            }
            "unsupported" => {
                assert!(
                    matches!(classification,Classification::Unsupported(code) if code == fixture["expected"]["diagnostic"].as_str().unwrap()),
                    "{id}: {classification:?}"
                );
                denied += 1;
            }
            "rejected" => {
                assert!(
                    matches!(classification,Classification::Rejected(code) if code == fixture["expected"]["diagnostic"].as_str().unwrap()),
                    "{id}: {classification:?}"
                );
                denied += 1;
            }
            other => panic!("unexpected expectation {other}"),
        }
        let ctx = context_named(
            &source,
            id,
            if id == "C052" {
                "corpus-reference"
            } else {
                "authored-document"
            },
        );
        let validated = validate_sequential_response(
            &encoded(&response(&source, &ctx)),
            expected(&source, &ctx),
        )
        .unwrap();
        if let SequentialValidatedResponse::Admitted(receipt) = validated {
            assert!(!receipt.execution_authority);
            assert_eq!(receipt.state, "disabled");
        }
    }
    assert_eq!((supported, denied), (11, 12));
}

#[test]
fn independent_nonallowlisted_literals_and_separators() {
    for body in [
        "sh('first'); sh \"second\"",
        "sh /*ok*/ ('x')\n sh '''multiline\nvalue'''",
        "sh 'literal $HOME and \\u'",
        "sh \"\\$HOME\"",
        "sh '🙂\u{2028}\u{85}\u{7f}'",
    ] {
        // This odd backslash-u lacks four hex digits and is malformed.
        let source = program(body);
        if body.contains("\\u") {
            assert_eq!(
                source::classify(&source),
                Classification::Rejected("E_SOURCE_PARSE")
            );
            continue;
        }
        assert!(
            matches!(source::classify(&source), Classification::Supported(_)),
            "{body}"
        );
        let ctx = context(&source);
        let receipt = validate_sequential_response(
            &encoded(&response(&source, &ctx)),
            expected(&source, &ctx),
        )
        .unwrap();
        assert!(matches!(receipt, SequentialValidatedResponse::Admitted(_)));
    }
    for body in [
        "sh 'a' sh 'b'",
        "sh 'a'/*\n*/sh 'b'",
        "sh\n'a'",
        "this.sh 'a'",
        "sh('a','b')",
        "sh 'a' + 'b'",
    ] {
        assert!(
            !matches!(
                source::classify(&program(body)),
                Classification::Supported(_)
            ),
            "{body}"
        );
    }
}
#[test]
fn literal_escape_and_normalization_semantics() {
    assert_eq!(source::stage_id("A- B"), "a--b");
    assert_eq!(source::stage_id("A-- B"), "a---b");
    assert_eq!(source::stage_id("A-  B"), "a--b");
    assert_eq!(source::stage_id("K"), "");
    assert_eq!(source::stage_id("É.BUILD_🙂"), ".build_");
    for quote in ["'", "\"", "'''", "\"\"\""] {
        for (escape, wanted) in [
            ("\\\\", "\\"),
            ("\\'", "'"),
            ("\\\"", "\""),
            ("\\$", "$"),
            ("\\n", "\n"),
            ("\\r", "\r"),
            ("\\t", "\t"),
            ("\\b", "\u{8}"),
            ("\\f", "\u{c}"),
        ] {
            let src = program(&format!("sh {quote}{escape}{quote}"));
            let Classification::Supported(stages) = source::classify(&src) else {
                panic!("{quote} {escape}")
            };
            assert_eq!(stages[0].scripts, [wanted]);
        }
    }
    let src = program("sh 'a\\\\u0041'");
    let Classification::Supported(stages) = source::classify(&src) else {
        panic!()
    };
    assert_eq!(stages[0].scripts, ["a\\u0041"]);
}
#[test]
fn source_byte_stage_step_and_aggregate_bounds() {
    for bytes in [
        vec![0xff],
        b"\xef\xbb\xbfpipeline".to_vec(),
        b"pipeline\r\n".to_vec(),
        vec![0],
    ] {
        assert_eq!(
            source::classify(&bytes),
            Classification::Rejected("E_SOURCE_TEXT")
        );
    }
    assert_eq!(
        source::classify(&vec![0xff; 16385]),
        Classification::Rejected("E_SOURCE_TOO_LARGE")
    );
    for (name, supported) in [
        ("a".repeat(96), true),
        ("a".repeat(97), false),
        ("é".repeat(48) + "a", false),
    ] {
        let src = format!(
            "pipeline {{ agent any; stages {{ stage('{name}') {{ steps {{ sh 'x' }} }} }} }}"
        );
        assert_eq!(
            matches!(
                source::classify(src.as_bytes()),
                Classification::Supported(_)
            ),
            supported
        );
    }
    let stages = (0..32)
        .map(|i| format!("stage('s{i}') {{ steps {{ sh 'x' }} }}"))
        .collect::<Vec<_>>()
        .join(";");
    assert!(matches!(
        source::classify(format!("pipeline {{ agent any; stages {{ {stages} }} }}").as_bytes()),
        Classification::Supported(_)
    ));
    let base = program("sh 'x'");
    let mut limit = base.clone();
    limit.resize(16384, b' ');
    assert!(matches!(
        source::classify(&limit),
        Classification::Supported(_)
    ));
    limit.push(b' ');
    assert_eq!(
        source::classify(&limit),
        Classification::Rejected("E_SOURCE_TOO_LARGE")
    );
    let steps64 = program(&vec!["sh 'x'"; 64].join(";"));
    assert!(matches!(
        source::classify(&steps64),
        Classification::Supported(_)
    ));
    assert_eq!(
        source::classify(&program(&vec!["sh 'x'"; 65].join(";"))),
        Classification::Unsupported("E_STEP_LIMIT")
    );
    assert!(matches!(
        source::classify(&program(&format!("sh '{}'", "é".repeat(2048)))),
        Classification::Supported(_)
    ));
    assert_eq!(
        source::classify(&program(&format!("sh '{}'; sh 'x'", "é".repeat(2048)))),
        Classification::Unsupported("E_STEP_ARGUMENT")
    );
    assert_eq!(
        source::classify(&program(&format!("sh '{}'", "é".repeat(2049)))),
        Classification::Unsupported("E_STEP_ARGUMENT")
    );
}
#[test]
fn contexts_and_requests_are_canonical_bound_and_versioned() {
    let source = program("sh 'ok'");
    let ctx = context(&source);
    let request = sequential_request(expected(&source, &ctx)).unwrap();
    assert!(request.ends_with(b"\n"));
    let parsed = canonical(&request, 262144, "E_REQUEST_INVALID").unwrap();
    let Edn::Map(fields) = parsed else { panic!() };
    expect_string(&fields, "protocol", PROTOCOL).unwrap();
    expect_string(&fields, "target-contract-sha256", CONTRACT_SHA256).unwrap();
    for changed in [
        ctx.canonical[..ctx.canonical.len() - 1].to_vec(),
        [ctx.canonical.as_slice(), b"\n"].concat(),
        b"{}\n".to_vec(),
        vec![b'x'; 2049],
    ] {
        assert!(parse_document_context(&changed, &source).is_err());
    }
    let other = program("sh 'other'");
    assert!(sequential_request(expected(&other, &ctx)).is_err());
    assert!(validate_sequential_response(b"{}\n", expected(&other, &ctx)).is_err());
    for (key, value) in [
        ("document-id", text("bad:id")),
        ("origin-kind", keyword("live-job")),
        ("origin", text("bad\norigin")),
        ("source-sha256", text(&"0".repeat(64))),
        ("extra", Edn::Bool(false)),
    ] {
        let mut altered = ctx.value.clone();
        change(&mut altered, &[key], value);
        assert!(
            parse_document_context(&encoded(&altered), &source).is_err(),
            "{key}"
        );
    }
    let oversized = vec![b'x'; 16385];
    let bigctx = context(&oversized);
    assert!(sequential_request(expected(&oversized, &bigctx)).is_ok());
}
#[test]
fn self_consistent_worker_lowering_forgery_is_refused() {
    let source = program("sh 'first'; sh 'second'");
    let ctx = context(&source);
    let original = response(&source, &ctx);
    for (from, to) in [
        ("first", "forged"),
        ("\"-xe\"", "\"-e\""),
        ("/bin/sh", "/bin/false"),
        ("name: \"Build\"", "name: \"Changed\""),
    ] {
        let mut forged = original.clone();
        let Edn::Map(root) = &forged else { panic!() };
        let result = exact_map(
            field(root, "result").unwrap(),
            &[
                "agent-mapping",
                "definition-yaml",
                "definition-yaml-sha256",
                "pipeline-yaml",
                "pipeline-yaml-sha256",
                "semantic",
            ],
            "test",
        )
        .unwrap();
        let yaml = string_field(result, "pipeline-yaml")
            .unwrap()
            .replace(from, to);
        let digest = sha256_hex(yaml.as_bytes());
        let definition = definition_yaml(&ctx, &digest);
        change(&mut forged, &["result", "pipeline-yaml"], text(&yaml));
        change(
            &mut forged,
            &["result", "pipeline-yaml-sha256"],
            text(&digest),
        );
        change(
            &mut forged,
            &["result", "definition-yaml"],
            text(&definition),
        );
        change(
            &mut forged,
            &["result", "definition-yaml-sha256"],
            text(&sha256_hex(definition.as_bytes())),
        );
        assert!(
            validate_sequential_response(&encoded(&forged), expected(&source, &ctx)).is_err(),
            "{from}"
        );
    }
    for (path, value) in [
        (
            vec!["result", "agent-mapping", "mcloving-platform"],
            text("any"),
        ),
        (vec!["contract-sha256"], text(&"0".repeat(64))),
        (vec!["authority", "scheduler"], Edn::Bool(true)),
        (vec!["source-context", "origin"], text("forged")),
        (vec!["target-profile", "plugin-count"], Edn::Integer(91)),
        (vec!["result", "semantic", "steps"], Edn::Integer(1)),
    ] {
        let mut forged = original.clone();
        change(&mut forged, &path, value);
        assert!(
            validate_sequential_response(&encoded(&forged), expected(&source, &ctx)).is_err(),
            "{path:?}"
        );
    }
}
#[test]
fn cross_version_missing_lf_and_status_downgrades_fail() {
    let source = program("sh 'ok'");
    let ctx = context(&source);
    let good = encoded(&response(&source, &ctx));
    assert!(
        validate_sequential_response(&good[..good.len() - 1], expected(&source, &ctx)).is_err()
    );
    assert!(
        validate_sequential_response(&[good.as_slice(), b"\n"].concat(), expected(&source, &ctx))
            .is_err()
    );
    assert!(
        validate_sequential_response(
            include_bytes!("../../tests/fixtures/mig003-golden.edn"),
            expected(&source, &ctx)
        )
        .is_err()
    );
    let legacy = super::super::ExpectedAdmission {
        request_id: "test:sequential",
        job_id: "fresh-document",
        job_generation: "generation",
        source: &source,
    };
    assert!(super::super::validate_response(&good, legacy).is_err());
    for badsource in [program("echo 'outside'"), b"'unterminated".to_vec()] {
        let badctx = context(&badsource);
        let denial = response(&badsource, &badctx);
        assert!(validate_sequential_response(&encoded(&denial), expected(&source, &ctx)).is_err());
        let mut internal = denial.clone();
        change(
            &mut internal,
            &["diagnostic", "code"],
            text("E_WORKER_INTERNAL"),
        );
        assert!(
            validate_sequential_response(&encoded(&internal), expected(&badsource, &badctx))
                .is_err()
        );
        let mut wrong = denial;
        change(
            &mut wrong,
            &["diagnostic", "code"],
            text("E_SOURCE_TOO_LARGE"),
        );
        assert!(
            validate_sequential_response(&encoded(&wrong), expected(&badsource, &badctx)).is_err()
        );
    }
}

#[test]
fn public_errors_never_echo_untrusted_fields_or_diagnostics() {
    let source = program("sh 'private-marker'");
    let ctx = context(&source);
    let marker = "private-worker-marker";
    let mut bogus_context = ctx.value.clone();
    change(&mut bogus_context, &[marker], text(marker));
    let error = parse_document_context(&encoded(&bogus_context), &source).unwrap_err();
    assert_eq!(error.code, "E_DOCUMENT_CONTEXT");
    assert_eq!(error.message, "document context validation failed");
    assert!(!error.to_string().contains(marker));
    let good = response(&source, &ctx);
    for path in [
        vec![marker],
        vec!["result", marker],
        vec!["target-profile", marker],
        vec!["authority", marker],
    ] {
        let mut forged = good.clone();
        change(&mut forged, &path, text(marker));
        let error =
            validate_sequential_response(&encoded(&forged), expected(&source, &ctx)).unwrap_err();
        assert_eq!(error.message, "sequential response validation failed");
        assert!(!error.to_string().contains(marker));
    }
    let source = program("echo 'excluded'");
    let ctx = context(&source);
    let mut forged = response(&source, &ctx);
    change(&mut forged, &["diagnostic", "code"], text(marker));
    let error =
        validate_sequential_response(&encoded(&forged), expected(&source, &ctx)).unwrap_err();
    assert_eq!(error.code, "E_DIAGNOSTIC_CODE");
    assert!(!error.to_string().contains(marker));
}

#[test]
fn recognized_dsl_truncation_is_a_verified_parse_rejection() {
    // Every item ends at a known DSL token boundary inside an opened block or
    // argument. No suffix executes: this checks source recognition only.
    let prefixes = [
        "pipeline {",
        "pipeline { agent",
        "pipeline { agent any",
        "pipeline { agent any;",
        "pipeline { agent any; stages",
        "pipeline { agent any; stages {",
        "pipeline { agent any; stages { stage",
        "pipeline { agent any; stages { stage(",
        "pipeline { agent any; stages { stage('Build'",
        "pipeline { agent any; stages { stage('Build')",
        "pipeline { agent any; stages { stage('Build') {",
        "pipeline { agent any; stages { stage('Build') { steps",
        "pipeline { agent any; stages { stage('Build') { steps {",
        "pipeline { agent any; stages { stage('Build') { steps { sh",
        "pipeline { agent any; stages { stage('Build') { steps { sh(",
        "pipeline { agent any; stages { stage('Build') { steps { sh('ok'",
        "pipeline { agent any; stages { stage('Build') { steps { sh('ok')",
        "pipeline { agent any; stages { stage('Build') { steps { sh('ok') }",
        "pipeline { agent any; stages { stage('Build') { steps { sh('ok') } }",
        "pipeline { agent any; stages { stage('Build') { steps { sh('ok') } } }",
    ];
    // Fixed minimal worker parse-rejection envelope. It does not derive its
    // status/code from the recognizer being tested.
    let legacy = super::super::parse_canonical_response(include_bytes!(
        "../../tests/fixtures/mig003-golden.edn"
    ))
    .unwrap();
    let Edn::Map(legacy) = legacy else { panic!() };
    let parse_rejection = encoded(&map(vec![
        ("authority", field(&legacy, "authority").unwrap().clone()),
        ("compiler", text(COMPILER)),
        ("protocol", text(PROTOCOL)),
        ("status", keyword("rejected")),
        (
            "diagnostic",
            map(vec![
                ("code", text("E_SOURCE_PARSE")),
                (
                    "message",
                    text("request rejected without execution authority"),
                ),
            ]),
        ),
    ]));
    for prefix in prefixes {
        for suffix in [
            "",
            " ",
            "\n",
            " /* complete comment */",
            " // terminal comment",
            ";",
            "\n;;\n",
        ] {
            let source = format!("{prefix}{suffix}");
            assert_eq!(
                source::classify(source.as_bytes()),
                Classification::Rejected("E_SOURCE_PARSE"),
                "{source:?}"
            );
            let ctx = context(source.as_bytes());
            assert_eq!(
                validate_sequential_response(&parse_rejection, expected(source.as_bytes(), &ctx))
                    .unwrap(),
                SequentialValidatedResponse::Rejected {
                    code: "E_SOURCE_PARSE".to_owned()
                }
            );
        }
    }
    let complete = format!("{} }}", prefixes.last().unwrap());
    assert!(matches!(
        source::classify(complete.as_bytes()),
        Classification::Supported(_)
    ));
}

#[test]
fn eof_rule_does_not_guess_outside_subset_groovy_or_delimiters_in_literals() {
    // Outside forms without a completely recognized DSL prefix remain
    // unsupported/unclassified; this is not a full Groovy syntax checker.
    for source in [
        "",
        "pipeline",
        "pipeline \n /* comment */",
        "node {}",
        "unknown('x')",
        "pipeline()",
        "def x = '{'",
        "pipeline { unsupported(",
    ] {
        assert!(
            !matches!(
                source::classify(source.as_bytes()),
                Classification::Rejected("E_SOURCE_PARSE")
            ),
            "{source:?}"
        );
    }
    for body in [
        "sh '{ ('",
        "sh ') }'",
        "sh 'ok' /* { ( */",
        "sh 'ok' // } )\n",
    ] {
        assert!(
            matches!(
                source::classify(&program(body)),
                Classification::Supported(_)
            ),
            "{body}"
        );
    }
}

#[test]
fn mismatched_closers_and_nested_outside_forms_never_admit() {
    for source in [
        "pipeline { agent any; stages { stage('Build'} { steps { sh 'ok' } } } }",
        "pipeline { agent any; stages { stage('Build') { steps { sh('ok'} } } }",
        "pipeline { agent any; stages { stage('Build') { steps { if (true) { sh 'ok' } } } } }",
        "pipeline { agent any; stages { stage('Build') { steps { script { sh 'ok' } } } } }",
    ] {
        assert!(
            !matches!(
                source::classify(source.as_bytes()),
                Classification::Supported(_)
            ),
            "{source:?}"
        );
    }
}

fn assert_fixed_parse_rejection(source: &[u8]) {
    let ctx = context(source);
    let authority = map([
        "agent-protocol",
        "controller-filesystem",
        "controller-store",
        "credentials",
        "effects",
        "network",
        "scheduler",
        "workload-execution",
    ]
    .into_iter()
    .map(|key| (key, Edn::Bool(false)))
    .collect());
    let wire = encoded(&map(vec![
        ("authority", authority),
        ("compiler", text(COMPILER)),
        ("protocol", text(PROTOCOL)),
        ("status", keyword("rejected")),
        (
            "diagnostic",
            map(vec![
                ("code", text("E_SOURCE_PARSE")),
                (
                    "message",
                    text("request rejected without execution authority"),
                ),
            ]),
        ),
    ]));
    assert_eq!(
        source::classify(source),
        Classification::Rejected("E_SOURCE_PARSE"),
        "{source:?}"
    );
    assert_eq!(
        validate_sequential_response(&wire, expected(source, &ctx)).unwrap(),
        SequentialValidatedResponse::Rejected {
            code: "E_SOURCE_PARSE".to_owned()
        }
    );
}

#[test]
fn recognized_mismatched_closers_are_verified_parse_rejections() {
    for source in [
        "pipeline { agent any; stages { stage('Build'} { steps { sh 'ok' } } } }",
        "pipeline { agent any; stages { stage('Build') { steps { sh('ok'} } } }",
        "pipeline { agent any; stages { stage('Build'] { steps { sh 'ok' } } } }",
        "pipeline { agent any; stages { stage('Build') { steps { sh 'ok' ) } } }",
        "pipeline )",
        "pipeline { agent any; stages )",
        "pipeline { agent any; stages { stage('Build') { steps )",
        "pipeline { agent any; stages { stage('Build') { steps { sh 'ok' } } } } }",
    ] {
        assert_fixed_parse_rejection(source.as_bytes());
    }
    for source in [
        "pipeline {}",
        "pipeline { agent any; stages }",
        "pipeline { agent any; stages { stage } }",
        "pipeline { agent any; stages { stage('Build') { steps { sh } } } }",
    ] {
        assert!(
            matches!(
                source::classify(source.as_bytes()),
                Classification::Unsupported(_)
            ),
            "{source}"
        );
    }
}

#[test]
fn raw_unicode_preflight_distinguishes_malformed_from_valid_excluded_spelling() {
    let slash = char::from(92);
    for tail in [
        "u",
        "u0",
        "u00",
        "u000",
        "u00ZZ",
        "uu00ZZ",
        "u+041",
        "u-041",
        "u 041",
        "u0_41",
        "u００４１",
    ] {
        for count in [1, 3] {
            let escape = format!("{}{tail}", slash.to_string().repeat(count));
            for source in [
                program(&format!("sh '{escape}'")),
                format!("// {escape}\n").into_bytes(),
                format!("/* {escape} */").into_bytes(),
            ] {
                assert_fixed_parse_rejection(&source);
            }
        }
    }
    for tail in ["u0041", "uu0041", "uuu0041", "u00410"] {
        let source = program(&format!("sh '{slash}{tail}'"));
        assert_eq!(
            source::classify(&source),
            Classification::Unsupported("E_SOURCE_LEXICAL")
        );
    }
    for count in [2, 4] {
        for tail in ["u00ZZ", "u0041", "uu0041"] {
            let source = program(&format!("sh '{}{tail}'", slash.to_string().repeat(count)));
            assert!(matches!(
                source::classify(&source),
                Classification::Supported(_)
            ));
        }
    }
    assert_fixed_parse_rejection(format!("// {slash}u0041 {slash}uu00ZZ").as_bytes());
    // Raw preprocessing is nonrecursive: decoded backslash must not invent a
    // second eligible introducer. Valid spelling is still contract-excluded.
    assert_eq!(
        source::classify(format!("// {slash}u005cu00ZZ").as_bytes()),
        Classification::Unsupported("E_SOURCE_LEXICAL")
    );
}

#[test]
fn literal_errors_distinguish_groovy_syntax_from_contract_exclusions() {
    let slash = char::from(92);
    for quote in ["'", "\"", "'''", "\"\"\""] {
        // Independently verified against pinned Groovy PARSING: every
        // printable ASCII character plus physical LF/tab, in all quote forms.
        for escaped in (0x20_u8..=0x7e).map(char::from).chain(['\n', '\t']) {
            let tail = if escaped == 'u' {
                "u0041".to_owned()
            } else {
                escaped.to_string()
            };
            let source = program(&format!("sh {quote}{slash}{tail}{quote}"));
            match escaped {
                '"' | '$' | '\'' | '\\' | 'b' | 'f' | 'n' | 'r' | 't' => {
                    assert!(
                        matches!(source::classify(&source), Classification::Supported(_)),
                        "quote={quote:?} escaped={escaped:?}"
                    );
                }
                '0'..='7' | 'u' | '\n' => {
                    assert_eq!(
                        source::classify(&source),
                        Classification::Unsupported("E_SOURCE_LEXICAL"),
                        "quote={quote:?} escaped={escaped:?}"
                    );
                }
                _ => assert_fixed_parse_rejection(&source),
            }
        }
        for escaped in ['é', '🙂', '\u{1}', '\u{7f}'] {
            let source = program(&format!("sh {quote}{slash}{escaped}{quote}"));
            assert_eq!(source::classify(&source), Classification::Unclassified);
        }
        for tail in ["q", "a", "U0041", "8", "9", "v", "e", "?", "x41"] {
            assert_fixed_parse_rejection(&program(&format!("sh {quote}{slash}{tail}{quote}")));
        }
        for tail in ["0", "00", "000", "07", "123", "377", "400", "777", "\n"] {
            let source = program(&format!("sh {quote}{slash}{tail}{quote}"));
            assert_eq!(
                source::classify(&source),
                Classification::Unsupported("E_SOURCE_LEXICAL")
            );
        }
    }
    for quote in ["\"", "\"\"\""] {
        // Pinned Groovy PARSING independently rejects this finite family:
        // the apparent outer closer opens a nested expression string with
        // no possible closing quote in the rest of the source.
        for gap in ["", " ", "\t", "\n", "\u{c}"] {
            for suffix in ["", "\n}}}}", ");", "]"] {
                let truncated = format!(
                    "pipeline {{ agent any; stages {{ stage('Build') {{ steps {{ sh {quote}${{{gap}{quote}{suffix}"
                );
                assert_fixed_parse_rejection(truncated.as_bytes());
            }
            let truncated = format!(
                "pipeline {{ agent any; stages {{ stage('Build') {{ steps {{ sh {quote}${{{gap}"
            );
            assert_fixed_parse_rejection(truncated.as_bytes());
            assert_fixed_parse_rejection(&program(&format!("sh {quote}${{{gap}{quote}")));
        }
        for expression in [
            "", " ", "\"x\"", "'x'", " /x/ ", " /\\q/ ", "[a: 1]", " -> 'x' ", "'''x'''",
        ] {
            let valid_excluded = program(&format!("sh {quote}${{{expression}}}{quote}"));
            assert!(
                matches!(
                    source::classify(&valid_excluded),
                    Classification::Unsupported(_) | Classification::Unclassified
                ),
                "valid excluded interpolation must not be admitted or called malformed: {valid_excluded:?}"
            );
        }
        // These valid complex expressions remain outside this recognizer;
        // the existing lexer can disagree with Groovy after an inner quote.
        // This correction must not grant them execution or claim parity.
        for expression in [" /* \" */ 'x' ", "\"\"\"x\"\"\""] {
            let complex = program(&format!("sh {quote}${{{expression}}}{quote}"));
            assert!(!matches!(
                source::classify(&complex),
                Classification::Supported(_)
            ));
            // An attributed unsupported response must not become a verified
            // parse rejection merely because the provisional lexer disagrees.
            let ctx = context(&complex);
            let baseline = program("sh \"${foo}\"");
            let mut wire = response(&baseline, &context(&baseline));
            change(&mut wire, &["source-context"], ctx.value.clone());
            change(
                &mut wire,
                &["source"],
                map(vec![
                    ("bytes", Edn::Integer(complex.len() as i64)),
                    ("context-sha256", text(&ctx.context_sha256())),
                    ("sha256", text(&sha256_hex(&complex))),
                ]),
            );
            assert!(matches!(
                validate_sequential_response(&encoded(&wire), expected(&complex, &ctx)),
                Err(_) | Ok(SequentialValidatedResponse::Unsupported { .. })
            ));
        }
        for tail in ["", " ", "1", "-", "?"] {
            assert_fixed_parse_rejection(&program(&format!("sh {quote}${tail}{quote}")));
        }
        for tail in ["foo", "{foo}", "_foo", "é"] {
            assert_eq!(
                source::classify(&program(&format!("sh {quote}${tail}{quote}"))),
                Classification::Unsupported("E_STEP_DYNAMIC")
            );
        }
    }
    // Unknown escapes inside a dynamic expression may be slashy content;
    // ordinary outer-string rules cannot provide a verified syntax verdict.
    let dynamic = program(&format!("sh \"${{ /{slash}q/ }}\""));
    assert_eq!(source::classify(&dynamic), Classification::Unclassified);
    assert_eq!(
        source::classify(&program("sh \"${ '$?' }\"")),
        Classification::Unsupported("E_STEP_DYNAMIC")
    );
}
