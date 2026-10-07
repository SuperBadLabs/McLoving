//! CTRL-007: production startup must refuse malformed NAT64 policy before I/O.
use std::process::Command;

#[test]
fn shipped_controller_refuses_invalid_notification_nat64_prefix_configuration() {
    let root = tempfile::tempdir().unwrap();
    for invalid in [
        "2606:4700::/72",
        "",
        "2606:4700::1/96",
        "fc00::/96",
        "2606:4700::/96,",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_mcloving-controller"))
            .env_clear()
            .env(
                "MCLOVING_MIGRATION_DATABASE_URL",
                "postgresql://migration@localhost/unused?host=/ctrl007-no-database",
            )
            .env(
                "MCLOVING_DATABASE_URL",
                "postgresql://runtime@localhost/unused?host=/ctrl007-no-database",
            )
            .env("MCLOVING_API_TOKEN", "ctrl007-startup-api-token-32-bytes")
            .env(
                "MCLOVING_ARTIFACT_AGENT_TOKEN",
                "ctrl007-startup-artifact-token-32-bytes",
            )
            .env(
                "MCLOVING_ORGANIZATION_ID",
                "7bbaf4ac-1f1b-4182-9574-3c306e286585",
            )
            .env("MCLOVING_AGENT_ID", "ctrl007-startup")
            .env("MCLOVING_AGENT_CAPABILITIES", "disabled")
            .env("MCLOVING_AGENT_TRUST_POOL", "trusted-linux")
            .env("MCLOVING_LEASE_SECONDS", "30")
            .env("MCLOVING_POLL_MILLISECONDS", "10")
            .env("MCLOVING_CANCELLATION_POLL_MILLISECONDS", "50")
            .env("MCLOVING_TERMINATION_GRACE_MILLISECONDS", "100")
            .env("MCLOVING_SESSION_EPOCH", "1")
            .env("MCLOVING_WORKSPACE_ROOT", root.path().join("workspace"))
            .env("MCLOVING_AGENT_JOURNAL", root.path().join("journal.db"))
            .env("MCLOVING_OBJECT_ROOT", root.path().join("objects"))
            .env("MCLOVING_NOTIFICATION_NAT64_PREFIXES", invalid)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(
            error.contains("MCLOVING_NOTIFICATION_NAT64_PREFIXES"),
            "malformed policy must fail at startup by name before connecting to PostgreSQL: {invalid:?}: {error}"
        );
        assert!(
            !error.contains("connect migration database"),
            "policy was ignored: {error}"
        );
    }
}
