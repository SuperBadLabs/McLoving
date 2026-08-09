mod adapter;
mod authority;
mod config;
mod npm_adapter;
mod plan;
mod pypi_adapter;
mod request;
mod strict_json;

pub use adapter::{AdapterBindings, AdapterError, parse_maven_lock};
pub use authority::{AuthorityError, LoadedAuthorities};
pub use config::{
    AdapterConfig, CertifiedConfig, ConfigError, RepositoryConfig, RepositoryGrant, ResolverLimits,
    configuration_sha256, validate_config,
};
pub use npm_adapter::parse_npm_package_lock;

pub use plan::{
    CanonicalPlan, Ecosystem, PackageNode, PlanError, RepositoryBinding, SourceTrustClass,
    canonical_graph_sha256, canonical_node_id, validate_plan,
};
pub use pypi_adapter::parse_pypi_requirements;
pub use request::{
    AdmittedRequest, GrantUse, RequestError, ResolutionRequest, admit_request, request_sha256,
};

pub const PROTOCOL_VERSION: &str = "mcloving.dependency-resolver/v1";
pub const PLAN_SCHEMA_VERSION: &str = "mcloving.dependency-plan/v1";
pub const CONFIG_SCHEMA_VERSION: &str = "mcloving.dependency-config/v1";
pub const REQUEST_SCHEMA_VERSION: &str = "mcloving.dependency-request/v1";
