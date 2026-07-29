use std::collections::BTreeMap;
use std::str::FromStr;

use mcloving_pipeline_ir::{
    CompilerIdentity, ComponentCatalog, ComponentDigest, ComponentErrorCode, ComponentInvocation,
    ExpansionLimits, ParameterType, ParameterValue, ParseLimits, Provenance, VersionedComponent,
    compile_strict_yaml, expand_component,
};

const TEMPLATE_A: &str = r#"
version: 1
name: reusable
parameters:
  target:
    type: string
    default: linux
stages:
  - id: build
    name: Build
    steps:
      - process:
          program: echo
          args:
            - expression: parameters.target + "-release"
"#;

const TEMPLATE_B: &str = r#"
# Presentation and mapping order do not affect the component identity.
name: reusable
version: 1
parameters:
  target: {default: linux, type: string}
stages:
  - name: Build
    id: build
    steps:
      - process:
          args: [{expression: 'parameters.target + "-release"'}]
          program: echo
"#;

fn provenance(marker: u8) -> Provenance {
    Provenance {
        source_id: format!("fixture://component-{marker}"),
        source_sha256: [marker; 32],
        compiler: CompilerIdentity {
            name: "fixture".to_owned(),
            version: "1".to_owned(),
        },
    }
}

fn component(source: &str, marker: u8) -> VersionedComponent {
    VersionedComponent::new(
        "reusable",
        compile_strict_yaml("fixture://component", source, ParseLimits::default()).unwrap(),
        BTreeMap::from([("artifact".to_owned(), ParameterType::String)]),
        Vec::new(),
        provenance(marker),
    )
    .unwrap()
}

#[test]
fn references_are_exact_lowercase_sha256_only() {
    let digest = component(TEMPLATE_A, 1).semantic_digest().unwrap();
    assert_eq!(
        ComponentDigest::from_str(&digest.to_reference()).unwrap(),
        digest
    );
    for floating in [
        "reusable",
        "reusable:latest",
        "main",
        "sha256:ABCDEF",
        "sha256:1234",
    ] {
        assert!(ComponentDigest::from_str(floating).is_err(), "{floating}");
    }
}

#[test]
fn component_identity_is_presentation_independent_and_excludes_provenance() {
    let first = component(TEMPLATE_A, 1);
    let second = component(TEMPLATE_B, 9);
    assert_eq!(
        first.semantic_digest().unwrap(),
        second.semantic_digest().unwrap()
    );
}

#[test]
fn expansion_identity_excludes_source_presentation_provenance() {
    let first = component(TEMPLATE_A, 1);
    let second = component(TEMPLATE_B, 9);
    let digest = first.semantic_digest().unwrap();
    let invocation = ComponentInvocation {
        digest,
        inputs: BTreeMap::new(),
    };
    let mut first_catalog = ComponentCatalog::default();
    first_catalog.insert_exact(digest, first).unwrap();
    let mut second_catalog = ComponentCatalog::default();
    second_catalog.insert_exact(digest, second).unwrap();
    let first = expand_component(
        invocation.clone(),
        &first_catalog,
        ExpansionLimits::default(),
    )
    .unwrap();
    let second = expand_component(invocation, &second_catalog, ExpansionLimits::default()).unwrap();
    assert_eq!(
        first.canonical_bytes().unwrap(),
        second.canonical_bytes().unwrap()
    );
    assert_ne!(
        first.components[0].source_sha256,
        second.components[0].source_sha256
    );
}

#[test]
fn typed_inputs_expand_deterministically_with_provenance_and_outputs() {
    let dependency = component(TEMPLATE_A, 3);
    let dependency_digest = dependency.semantic_digest().unwrap();
    let root_pipeline = compile_strict_yaml(
        "fixture://root",
        TEMPLATE_A.replace("name: reusable", "name: root").as_str(),
        ParseLimits::default(),
    )
    .unwrap();
    let root = VersionedComponent::new(
        "root",
        root_pipeline,
        BTreeMap::from([("root_artifact".to_owned(), ParameterType::String)]),
        vec![ComponentInvocation {
            digest: dependency_digest,
            inputs: BTreeMap::from([(
                "target".to_owned(),
                ParameterValue::String("dependency".to_owned()),
            )]),
        }],
        provenance(4),
    )
    .unwrap();
    let root_digest = root.semantic_digest().unwrap();
    let mut catalog = ComponentCatalog::default();
    catalog.insert_exact(dependency_digest, dependency).unwrap();
    catalog.insert_exact(root_digest, root).unwrap();

    let invocation = ComponentInvocation {
        digest: root_digest,
        inputs: BTreeMap::from([(
            "target".to_owned(),
            ParameterValue::String("windows".to_owned()),
        )]),
    };
    let first = expand_component(invocation.clone(), &catalog, ExpansionLimits::default()).unwrap();
    let second = expand_component(invocation, &catalog, ExpansionLimits::default()).unwrap();
    assert_eq!(
        first.canonical_bytes().unwrap(),
        second.canonical_bytes().unwrap()
    );
    assert_eq!(first.components.len(), 2);
    assert_eq!(first.pipeline.stages.len(), 2);
    assert_eq!(first.pipeline.stages[0].id, "c1.build");
    assert_eq!(first.pipeline.stages[1].id, "c0.build");
    let dependency_arg = process_arg(&first.pipeline.stages[0].steps[0]);
    let root_arg = process_arg(&first.pipeline.stages[1].steps[0]);
    assert_eq!(dependency_arg, "dependency-release");
    assert_eq!(root_arg, "windows-release");
    assert_eq!(first.components[0].source_sha256, [4; 32]);
    assert_eq!(first.components[1].source_sha256, [3; 32]);
    assert_eq!(
        first.components[0].outputs["root_artifact"],
        ParameterType::String
    );
}

#[test]
fn wrong_types_missing_components_and_every_expansion_limit_fail_closed() {
    let item = component(TEMPLATE_A, 2);
    let digest = item.semantic_digest().unwrap();
    let mut catalog = ComponentCatalog::default();
    catalog.insert_exact(digest, item).unwrap();

    let wrong = expand_component(
        ComponentInvocation {
            digest,
            inputs: BTreeMap::from([("target".to_owned(), ParameterValue::Bool(true))]),
        },
        &catalog,
        ExpansionLimits::default(),
    )
    .unwrap_err();
    assert_eq!(wrong.code, ComponentErrorCode::InputType);

    let missing = expand_component(
        ComponentInvocation {
            digest: ComponentDigest::from_bytes([0; 32]),
            inputs: BTreeMap::new(),
        },
        &catalog,
        ExpansionLimits::default(),
    )
    .unwrap_err();
    assert_eq!(missing.code, ComponentErrorCode::MissingComponent);

    for (limits, code) in [
        (
            ExpansionLimits {
                max_depth: 0,
                ..ExpansionLimits::default()
            },
            ComponentErrorCode::InvalidLimits,
        ),
        (
            ExpansionLimits {
                max_components: 0,
                ..ExpansionLimits::default()
            },
            ComponentErrorCode::InvalidLimits,
        ),
        (
            ExpansionLimits {
                max_stages: 0,
                ..ExpansionLimits::default()
            },
            ComponentErrorCode::InvalidLimits,
        ),
        (
            ExpansionLimits {
                max_steps: 0,
                ..ExpansionLimits::default()
            },
            ComponentErrorCode::InvalidLimits,
        ),
        (
            ExpansionLimits {
                max_canonical_bytes: 1,
                ..ExpansionLimits::default()
            },
            ComponentErrorCode::ByteLimit,
        ),
    ] {
        let error = expand_component(
            ComponentInvocation {
                digest,
                inputs: BTreeMap::new(),
            },
            &catalog,
            limits,
        )
        .unwrap_err();
        assert_eq!(error.code, code);
    }

    let dependency = component(TEMPLATE_A, 4);
    let dependency_digest = dependency.semantic_digest().unwrap();
    let root = VersionedComponent::new(
        "root",
        compile_strict_yaml(
            "fixture://root-limits",
            &TEMPLATE_A.replace("name: reusable", "name: root"),
            ParseLimits::default(),
        )
        .unwrap(),
        BTreeMap::new(),
        vec![ComponentInvocation {
            digest: dependency_digest,
            inputs: BTreeMap::new(),
        }],
        provenance(5),
    )
    .unwrap();
    let root_digest = root.semantic_digest().unwrap();
    catalog.insert_exact(dependency_digest, dependency).unwrap();
    catalog.insert_exact(root_digest, root).unwrap();
    for (limits, code) in [
        (
            ExpansionLimits {
                max_depth: 1,
                ..ExpansionLimits::default()
            },
            ComponentErrorCode::DepthLimit,
        ),
        (
            ExpansionLimits {
                max_components: 1,
                ..ExpansionLimits::default()
            },
            ComponentErrorCode::ComponentLimit,
        ),
        (
            ExpansionLimits {
                max_stages: 1,
                ..ExpansionLimits::default()
            },
            ComponentErrorCode::StageLimit,
        ),
        (
            ExpansionLimits {
                max_steps: 1,
                ..ExpansionLimits::default()
            },
            ComponentErrorCode::StepLimit,
        ),
    ] {
        let error = expand_component(
            ComponentInvocation {
                digest: root_digest,
                inputs: BTreeMap::new(),
            },
            &catalog,
            limits,
        )
        .unwrap_err();
        assert_eq!(error.code, code);
    }
}

#[test]
fn digest_mismatch_and_component_substitution_are_rejected() {
    let first = component(TEMPLATE_A, 1);
    let digest = first.semantic_digest().unwrap();
    let mut catalog = ComponentCatalog::default();
    let error = catalog
        .insert_exact(ComponentDigest::from_bytes([9; 32]), first.clone())
        .unwrap_err();
    assert_eq!(error.code, ComponentErrorCode::DigestMismatch);

    catalog.insert_exact(digest, first).unwrap();
    let changed = VersionedComponent::new(
        "reusable",
        compile_strict_yaml(
            "fixture://changed",
            &TEMPLATE_A.replace("program: echo", "program: printf"),
            ParseLimits::default(),
        )
        .unwrap(),
        BTreeMap::from([("artifact".to_owned(), ParameterType::String)]),
        Vec::new(),
        provenance(1),
    )
    .unwrap();
    assert_ne!(changed.semantic_digest().unwrap(), digest);
    let error = catalog.insert_exact(digest, changed).unwrap_err();
    assert_eq!(error.code, ComponentErrorCode::DigestMismatch);
}

#[test]
fn expansion_digest_binds_exact_component_even_for_equal_concrete_steps() {
    let first = component(TEMPLATE_A, 1);
    let second = VersionedComponent::new(
        "other-name",
        first.pipeline.clone(),
        first.outputs.clone(),
        Vec::new(),
        provenance(1),
    )
    .unwrap();
    let first_digest = first.semantic_digest().unwrap();
    let second_digest = second.semantic_digest().unwrap();
    let mut catalog = ComponentCatalog::default();
    catalog.insert_exact(first_digest, first).unwrap();
    catalog.insert_exact(second_digest, second).unwrap();
    let expand = |digest| {
        expand_component(
            ComponentInvocation {
                digest,
                inputs: BTreeMap::new(),
            },
            &catalog,
            ExpansionLimits::default(),
        )
        .unwrap()
    };
    let first = expand(first_digest);
    let second = expand(second_digest);
    assert_eq!(first.pipeline.stages, second.pipeline.stages);
    assert_ne!(
        first.semantic_digest().unwrap(),
        second.semantic_digest().unwrap()
    );
}

fn process_arg(step: &mcloving_pipeline_ir::Step) -> &str {
    match step {
        mcloving_pipeline_ir::Step::Process(process) => &process.args[0],
    }
}
