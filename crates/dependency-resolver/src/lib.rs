mod plan;

pub use plan::{
    CanonicalPlan, Ecosystem, PackageNode, PlanError, RepositoryBinding, SourceTrustClass,
    canonical_graph_sha256, canonical_node_id, validate_plan,
};

pub const PROTOCOL_VERSION: &str = "mcloving.dependency-resolver/v1";
pub const PLAN_SCHEMA_VERSION: &str = "mcloving.dependency-plan/v1";
