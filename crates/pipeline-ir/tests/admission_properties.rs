use mcloving_pipeline_ir::{ParseLimits, compile_strict_yaml, parse_strict};
use proptest::prelude::*;

const TEMPLATE: &str = r#"
version: 1
name: deterministic
stages:
  - id: stage
    name: Stage
    steps:
      - process:
          program: echo
          args: ["payload"]
"#;

proptest! {
    #[test]
    fn arbitrary_text_never_panics(source in ".{0,512}") {
        let _ = parse_strict(&source, ParseLimits::default());
    }

    #[test]
    fn admission_is_deterministic(comment in "[A-Za-z0-9 ]{0,80}") {
        let source = format!("# {comment}\n{TEMPLATE}");
        let first = compile_strict_yaml("property://first", &source, ParseLimits::default());
        let second = compile_strict_yaml("property://second", &source, ParseLimits::default());
        prop_assert_eq!(
            first.as_ref().map(|pipeline| pipeline.canonical_bytes().unwrap()),
            second.as_ref().map(|pipeline| pipeline.canonical_bytes().unwrap())
        );
        prop_assert_eq!(
            first.as_ref().map(|pipeline| pipeline.semantic_digest().unwrap()),
            second.as_ref().map(|pipeline| pipeline.semantic_digest().unwrap())
        );
    }

    #[test]
    fn unknown_root_fields_are_always_rejected(
        field in "[a-z][a-z0-9_]{0,24}",
        value in "[A-Za-z0-9]{1,32}",
    ) {
        prop_assume!(!matches!(field.as_str(), "version" | "name" | "stages"));
        let source = format!("{TEMPLATE}\n{field}: {value}\n");
        let error = compile_strict_yaml("property://unknown", &source, ParseLimits::default())
            .expect_err("unknown fields must fail closed");
        prop_assert!(error.message.contains("unknown field"));
    }

    #[test]
    fn sequence_expansion_is_bounded(count in 0_usize..128) {
        let values = std::iter::repeat_n("item", count).collect::<Vec<_>>().join(", ");
        let source = format!("values: [{values}]\n");
        let limit = 32;
        let result = parse_strict(
            &source,
            ParseLimits {
                max_sequence_items: limit,
                ..ParseLimits::default()
            },
        );
        prop_assert_eq!(result.is_ok(), count <= limit);
    }
}
