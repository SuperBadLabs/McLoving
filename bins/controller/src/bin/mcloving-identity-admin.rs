use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use mcloving_controller_store::{IdentityLifecycle, NewHumanIdentity, Store};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<()> {
    let mut command = Command::from_environment()?;
    let database_url = std::env::var("MCLOVING_MIGRATION_DATABASE_URL")
        .context("MCLOVING_MIGRATION_DATABASE_URL is required")?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .context("connect to PostgreSQL migration role")?;
    let store = Store::new(pool.clone());
    store.migrate().await.context("migrate controller store")?;

    match command.action.as_str() {
        "provision-human" => {
            let organization_id = command.uuid("organization")?;
            let identity_id = command.uuid("identity")?;
            let provider_id = command.uuid("provider")?;
            let subject = command.required("subject")?;
            let external_subject = command.required("external-subject")?;
            let source_realm_digest = command.digest("source-realm-sha256")?;
            let source_identity_id = command.required("source-identity")?;
            let source_membership_generation =
                command.positive_i64("source-membership-generation")?;
            let alias_history = command
                .optional("aliases")
                .map(|aliases| {
                    aliases
                        .split(',')
                        .filter(|alias| !alias.is_empty())
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let provenance_digest = command.digest("provenance-sha256")?;
            let actor_subject = command.required("actor")?;
            command.finish()?;
            store
                .provision_human_identity(&NewHumanIdentity {
                    organization_id,
                    identity_id,
                    subject,
                    provider_id,
                    external_subject,
                    source_realm_digest,
                    source_identity_id,
                    source_membership_generation,
                    alias_history,
                    provenance_digest,
                    actor_subject,
                })
                .await
                .context("provision reviewed human identity mapping")?;
            println!("identity_id={identity_id} provisioned=true");
        }
        "lifecycle" => {
            let organization_id = command.uuid("organization")?;
            let identity_id = command.uuid("identity")?;
            let expected_generation = command.positive_i64("expected-generation")?;
            let state = parse_lifecycle(&command.required("state")?)?;
            let actor = command.required("actor")?;
            command.finish()?;
            let generation = store
                .transition_identity_lifecycle(
                    organization_id,
                    identity_id,
                    expected_generation,
                    state,
                    &actor,
                )
                .await
                .context("transition identity lifecycle")?;
            println!("identity_id={identity_id} lifecycle_generation={generation}");
        }
        "revoke-service-credential" => {
            let organization_id = command.uuid("organization")?;
            let credential_id = command.uuid("credential")?;
            let reason = command.required("reason")?;
            let actor = command.required("actor")?;
            command.finish()?;
            let revoked = store
                .revoke_service_credential(
                    organization_id,
                    credential_id,
                    unix_time_ms(),
                    &reason,
                    &actor,
                )
                .await
                .context("revoke service credential")?;
            println!("credential_id={credential_id} revoked={revoked}");
        }
        action => bail!(
            "unsupported identity-admin action {action:?}; expected provision-human, lifecycle, or revoke-service-credential"
        ),
    }
    pool.close().await;
    Ok(())
}

struct Command {
    action: String,
    options: BTreeMap<String, String>,
}

impl Command {
    fn from_environment() -> Result<Self> {
        Self::parse(std::env::args().skip(1))
    }

    fn parse(arguments: impl IntoIterator<Item = String>) -> Result<Self> {
        let mut arguments = arguments.into_iter();
        let action = arguments
            .next()
            .context("identity-admin action is required")?;
        let mut options = BTreeMap::new();
        while let Some(flag) = arguments.next() {
            let name = flag
                .strip_prefix("--")
                .filter(|name| !name.is_empty())
                .with_context(|| format!("expected --name flag, got {flag:?}"))?;
            let value = arguments
                .next()
                .with_context(|| format!("flag --{name} requires a value"))?;
            if options.insert(name.to_owned(), value).is_some() {
                bail!("flag --{name} was supplied more than once");
            }
        }
        Ok(Self { action, options })
    }

    fn required(&mut self, name: &str) -> Result<String> {
        self.options
            .remove(name)
            .with_context(|| format!("--{name} is required"))
    }

    fn optional(&mut self, name: &str) -> Option<String> {
        self.options.remove(name)
    }

    fn uuid(&mut self, name: &str) -> Result<Uuid> {
        self.required(name)?
            .parse()
            .with_context(|| format!("--{name} must be a UUID"))
    }

    fn positive_i64(&mut self, name: &str) -> Result<i64> {
        let value = self
            .required(name)?
            .parse::<i64>()
            .with_context(|| format!("--{name} must be a positive integer"))?;
        if value <= 0 {
            bail!("--{name} must be a positive integer");
        }
        Ok(value)
    }

    fn digest(&mut self, name: &str) -> Result<[u8; 32]> {
        parse_sha256(&self.required(name)?)
            .with_context(|| format!("--{name} must contain exactly 64 hexadecimal characters"))
    }

    fn finish(self) -> Result<()> {
        if let Some(name) = self.options.keys().next() {
            bail!("unsupported flag --{name}");
        }
        Ok(())
    }
}

fn parse_lifecycle(value: &str) -> Result<IdentityLifecycle> {
    match value {
        "active" => Ok(IdentityLifecycle::Active),
        "disabled" => Ok(IdentityLifecycle::Disabled),
        "deleted" => Ok(IdentityLifecycle::Deleted),
        _ => bail!("--state must be active, disabled, or deleted"),
    }
}

fn parse_sha256(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 {
        bail!("digest length is not 64");
    }
    let mut digest = [0_u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .context("digest contains a non-hexadecimal character")?;
    }
    Ok(digest)
}

fn unix_time_ms() -> i64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    i64::try_from(millis).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_parser_rejects_duplicates_and_unknown_flags() {
        assert!(Command::parse(["lifecycle".to_owned(), "--state".to_owned()]).is_err());
        assert!(
            Command::parse([
                "lifecycle".to_owned(),
                "--state".to_owned(),
                "active".to_owned(),
                "--state".to_owned(),
                "disabled".to_owned(),
            ])
            .is_err()
        );
        let command = Command::parse([
            "lifecycle".to_owned(),
            "--extra".to_owned(),
            "value".to_owned(),
        ])
        .expect("parse syntactically valid flags");
        assert_eq!(command.action, "lifecycle");
        assert!(command.finish().is_err());
    }

    #[test]
    fn digest_and_lifecycle_inputs_are_strict() {
        assert_eq!(
            parse_sha256(&"ab".repeat(32)).expect("valid digest"),
            [0xab; 32]
        );
        assert!(parse_sha256("ab").is_err());
        assert!(parse_sha256(&"zz".repeat(32)).is_err());
        assert!(matches!(
            parse_lifecycle("disabled").expect("known lifecycle"),
            IdentityLifecycle::Disabled
        ));
        assert!(parse_lifecycle("enabled").is_err());
    }
}
