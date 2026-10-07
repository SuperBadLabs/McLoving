//! Durable, fenced whole-set publication. Member transactions hold only the
//! member row during transport, never the attempt/session row needed by renewal.
//! Mutation order: attempt advisory when needed -> sorted members -> set ->
//! short restore/session authorization -> sorted deletion fences -> object rows.
//! Expiry owns sets before acquiring its short restore fence.
use super::*;
use mcloving_domain::artifacts::{
    ArtifactManifestMember, artifact_manifest_digest, validate_manifest,
};

#[derive(Clone, Debug)]
pub struct ArtifactSetAuthority {
    pub organization_id: Uuid,
    pub attempt_id: Uuid,
    pub fence: i64,
    pub restore_epoch: i64,
    pub agent_id: String,
    pub session_epoch: u64,
}
#[derive(Clone, Debug)]
pub struct ArtifactSetMember {
    pub name: String,
    pub bytes: u64,
    pub media_type: String,
    pub digest: Option<[u8; 32]>,
    pub pending_token: Option<String>,
}
pub struct ArtifactMemberClaim {
    tx: Transaction<'static, Postgres>,
    authority: ArtifactSetAuthority,
    set_id: [u8; 32],
    pub member: ArtifactSetMember,
}
async fn authorize(
    tx: &mut Transaction<'_, Postgres>,
    a: &ArtifactSetAuthority,
    abort: bool,
) -> Result<(), StoreError> {
    acquire_restore_fence_shared(tx).await?;
    if !Store::lock_agent_session(tx, &a.agent_id, a.session_epoch).await? {
        return Err(StoreError::InvalidAgentSession);
    }
    // These locks are acquired only in short begin/register/commit/abort phases.
    // Cancellation and lease expiry are rechecked at the availability boundary.
    let valid = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM attempts a JOIN nodes n ON n.id=a.node_id AND n.organization_id=a.organization_id JOIN builds b ON b.id=n.build_id AND b.organization_id=n.organization_id
         WHERE a.organization_id=$1 AND a.id=$2 AND a.fence=$3 AND a.restore_epoch=$4
         AND a.restore_epoch=(SELECT restore_epoch FROM controller_metadata WHERE singleton)
         AND a.lease_owner=$5 AND a.lease_expires_at>clock_timestamp()
         AND (a.status IN ('accepted','running','finalizing') OR ($6 AND a.status='cancelling'))
         AND ($6 OR b.cancellation_requested_at IS NULL))")
        .bind(a.organization_id).bind(a.attempt_id).bind(a.fence).bind(a.restore_epoch).bind(&a.agent_id).bind(abort)
        .fetch_one(&mut **tx).await?;
    if !valid {
        return Err(StoreError::InvalidAgentSession);
    }
    Ok(())
}
async fn attempt_lock(
    tx: &mut Transaction<'_, Postgres>,
    a: &ArtifactSetAuthority,
) -> Result<(), StoreError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!(
            "mcloving.artifact.attempt.{}.{}.{}",
            a.organization_id, a.attempt_id, a.fence
        ))
        .execute(&mut **tx)
        .await?;
    Ok(())
}
fn digest(value: Vec<u8>) -> Result<[u8; 32], StoreError> {
    value
        .try_into()
        .map_err(|_| StoreError::InvalidObjectRecord("artifact digest length".into()))
}
impl Store {
    pub async fn begin_artifact_set(
        &self,
        a: &ArtifactSetAuthority,
        set_id: [u8; 32],
        members: &[ArtifactManifestMember],
    ) -> Result<(), StoreError> {
        let bytes = validate_manifest(members)
            .map_err(|e| StoreError::InvalidObjectRecord(e.to_string()))?;
        if artifact_manifest_digest(members) != set_id {
            return Err(StoreError::InvalidObjectRecord(
                "artifact manifest digest".into(),
            ));
        }
        let mut tx = self.tenant_transaction(a.organization_id).await?;
        attempt_lock(&mut tx, a).await?;
        let existing=sqlx::query_as::<_,(Vec<u8>,String)>("SELECT set_id,state FROM artifact_sets WHERE organization_id=$1 AND attempt_id=$2 AND fence=$3 FOR UPDATE")
            .bind(a.organization_id).bind(a.attempt_id).bind(a.fence).fetch_optional(&mut *tx).await?;
        authorize(&mut tx, a, false).await?;
        if let Some((id, state)) = existing {
            if id.as_slice() != set_id.as_slice() || state == "aborted" {
                return Err(StoreError::InvalidObjectRecord(
                    "artifact set identity conflict or aborted set".into(),
                ));
            }
            tx.commit().await?;
            return Ok(());
        }
        let used = artifact_bytes_used(&mut tx, a.organization_id, a.attempt_id, a.fence).await?;
        let count = artifact_count_used(&mut tx, a.organization_id, a.attempt_id, a.fence).await?;
        if used.saturating_add(bytes as i64)
            > mcloving_domain::artifacts::MAX_ATTEMPT_ARTIFACT_BYTES as i64
            || count.saturating_add(members.len() as i64)
                > mcloving_domain::artifacts::MAX_ARTIFACT_FILES_PER_ATTEMPT as i64
        {
            return Err(StoreError::ArtifactQuota);
        }
        sqlx::query("INSERT INTO artifact_sets(organization_id,attempt_id,fence,restore_epoch,set_id,state,bytes,objects) VALUES($1,$2,$3,$4,$5,'staging',$6,$7)")
            .bind(a.organization_id).bind(a.attempt_id).bind(a.fence).bind(a.restore_epoch).bind(set_id.as_slice()).bind(bytes as i64).bind(members.len() as i64).execute(&mut *tx).await?;
        for m in members {
            sqlx::query("INSERT INTO artifact_set_members(organization_id,attempt_id,fence,set_id,name,bytes,media_type) VALUES($1,$2,$3,$4,$5,$6,$7)")
                .bind(a.organization_id).bind(a.attempt_id).bind(a.fence).bind(set_id.as_slice()).bind(&m.name).bind(m.bytes as i64).bind(&m.media_type).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }
    pub async fn claim_artifact_set_member(
        &self,
        a: &ArtifactSetAuthority,
        set_id: [u8; 32],
        name: &str,
    ) -> Result<ArtifactMemberClaim, StoreError> {
        // Authenticate in a separate short transaction so the held transport
        // transaction cannot block session churn, restoration or lease renewal.
        let mut auth = self.tenant_transaction(a.organization_id).await?;
        authorize(&mut auth, a, false).await?;
        auth.commit().await?;
        let mut tx = self.tenant_transaction(a.organization_id).await?;
        let row=sqlx::query_as::<_,(String,i64,String,Option<Vec<u8>>,Option<String>)>(
            "SELECT m.name,m.bytes,m.media_type,m.object_digest,m.pending_token FROM artifact_set_members m JOIN artifact_sets s USING(organization_id,attempt_id,fence,set_id)
             WHERE m.organization_id=$1 AND m.attempt_id=$2 AND m.fence=$3 AND m.set_id=$4 AND m.name=$5 AND s.state IN ('staging','available') FOR UPDATE OF m")
            .bind(a.organization_id).bind(a.attempt_id).bind(a.fence).bind(set_id.as_slice()).bind(name).fetch_optional(&mut *tx).await?
            .ok_or_else(|| StoreError::InvalidObjectRecord("artifact member absent or aborted".into()))?;
        let member = ArtifactSetMember {
            name: row.0,
            bytes: row.1 as u64,
            media_type: row.2,
            digest: row.3.map(digest).transpose()?,
            pending_token: row.4,
        };
        Ok(ArtifactMemberClaim {
            tx,
            authority: a.clone(),
            set_id,
            member,
        })
    }
    pub async fn artifact_set_members(
        &self,
        a: &ArtifactSetAuthority,
        set_id: [u8; 32],
    ) -> Result<Vec<ArtifactSetMember>, StoreError> {
        let mut tx = self.tenant_transaction(a.organization_id).await?;
        authorize(&mut tx, a, false).await?;
        let rows=sqlx::query_as::<_,(String,i64,String,Option<Vec<u8>>,Option<String>)>(
            "SELECT m.name,m.bytes,m.media_type,m.object_digest,m.pending_token FROM artifact_set_members m JOIN artifact_sets s USING(organization_id,attempt_id,fence,set_id)
             WHERE m.organization_id=$1 AND m.attempt_id=$2 AND m.fence=$3 AND m.set_id=$4 AND s.state IN ('staging','available') ORDER BY m.name")
            .bind(a.organization_id).bind(a.attempt_id).bind(a.fence).bind(set_id.as_slice()).fetch_all(&mut *tx).await?;
        tx.commit().await?;
        rows.into_iter()
            .map(|r| {
                Ok(ArtifactSetMember {
                    name: r.0,
                    bytes: r.1 as u64,
                    media_type: r.2,
                    digest: r.3.map(digest).transpose()?,
                    pending_token: r.4,
                })
            })
            .collect()
    }
    pub async fn commit_artifact_set(
        &self,
        a: &ArtifactSetAuthority,
        set_id: [u8; 32],
    ) -> Result<(), StoreError> {
        let mut tx = self.tenant_transaction(a.organization_id).await?;
        attempt_lock(&mut tx, a).await?;
        // Lock every member before the set row, the same ordering abort uses;
        // no availability is possible while a stage/retry claim is held.
        sqlx::query("SELECT name FROM artifact_set_members WHERE organization_id=$1 AND attempt_id=$2 AND fence=$3 AND set_id=$4 ORDER BY name FOR UPDATE")
            .bind(a.organization_id).bind(a.attempt_id).bind(a.fence).bind(set_id.as_slice()).fetch_all(&mut *tx).await?;
        let expected=sqlx::query_as::<_,(i64,String)>("SELECT objects,state FROM artifact_sets WHERE organization_id=$1 AND attempt_id=$2 AND fence=$3 AND set_id=$4 FOR UPDATE")
            .bind(a.organization_id).bind(a.attempt_id).bind(a.fence).bind(set_id.as_slice()).fetch_optional(&mut *tx).await?.ok_or_else(||StoreError::InvalidObjectRecord("artifact set absent".into()))?;
        authorize(&mut tx, a, false).await?;
        if expected.1 == "aborted" {
            return Err(StoreError::InvalidObjectRecord(
                "artifact set aborted".into(),
            ));
        }
        let ready=sqlx::query_scalar::<_,i64>("SELECT count(*) FROM artifact_set_members m JOIN attempt_objects o ON o.organization_id=m.organization_id AND o.attempt_id=m.attempt_id AND o.fence=m.fence AND o.name=m.name AND o.kind='artifact' AND o.artifact_set_id=m.set_id AND o.object_digest=m.object_digest AND o.bytes=m.bytes AND o.media_type=m.media_type WHERE m.organization_id=$1 AND m.attempt_id=$2 AND m.fence=$3 AND m.set_id=$4 AND m.pending_token IS NOT NULL AND o.status IN ('pending','available')")
            .bind(a.organization_id).bind(a.attempt_id).bind(a.fence).bind(set_id.as_slice()).fetch_one(&mut *tx).await?;
        if ready != expected.0 {
            return Err(StoreError::InvalidObjectRecord(
                "artifact set incomplete".into(),
            ));
        }
        let digests=sqlx::query_scalar::<_,Vec<u8>>("SELECT object_digest FROM artifact_set_members WHERE organization_id=$1 AND attempt_id=$2 AND fence=$3 AND set_id=$4 ORDER BY object_digest")
            .bind(a.organization_id).bind(a.attempt_id).bind(a.fence).bind(set_id.as_slice()).fetch_all(&mut *tx).await?;
        for d in digests {
            acquire_object_deletion_fence(&mut tx, &digest(d)?).await?;
        }
        // Recheck cancellation under row locks shared with cancellation updates.
        sqlx::query("SELECT a.id FROM attempts a JOIN nodes n ON n.id=a.node_id AND n.organization_id=a.organization_id JOIN builds b ON b.id=n.build_id AND b.organization_id=n.organization_id WHERE a.organization_id=$1 AND a.id=$2 FOR SHARE OF a,b")
            .bind(a.organization_id).bind(a.attempt_id).fetch_all(&mut *tx).await?;
        authorize(&mut tx, a, false).await?;
        sqlx::query("UPDATE attempt_objects SET status='available',checked_at=clock_timestamp() WHERE organization_id=$1 AND attempt_id=$2 AND fence=$3 AND artifact_set_id=$4 AND kind='artifact' AND status='pending'")
            .bind(a.organization_id).bind(a.attempt_id).bind(a.fence).bind(set_id.as_slice()).execute(&mut *tx).await?;
        sqlx::query("UPDATE artifact_sets SET state='available' WHERE organization_id=$1 AND attempt_id=$2 AND fence=$3 AND set_id=$4")
            .bind(a.organization_id).bind(a.attempt_id).bind(a.fence).bind(set_id.as_slice()).execute(&mut *tx).await?;
        let build=sqlx::query_scalar::<_,Uuid>("SELECT n.build_id FROM attempts a JOIN nodes n ON n.id=a.node_id AND n.organization_id=a.organization_id WHERE a.organization_id=$1 AND a.id=$2")
            .bind(a.organization_id).bind(a.attempt_id).fetch_one(&mut *tx).await?;
        if expected.1 != "available" {
            let objects=sqlx::query_as::<_,(String,Vec<u8>,i64,String)>("SELECT name,object_digest,bytes,media_type FROM artifact_set_members WHERE organization_id=$1 AND attempt_id=$2 AND fence=$3 AND set_id=$4 ORDER BY name")
                .bind(a.organization_id).bind(a.attempt_id).bind(a.fence).bind(set_id.as_slice()).fetch_all(&mut *tx).await?;
            for (name, d, bytes, media_type) in objects {
                append_event_and_outbox(&mut tx,a.organization_id,build,"artifact.committed",json!({"attempt_id":a.attempt_id,"fence":a.fence,"name":name,"sha256":hex_digest(&digest(d)?),"bytes":bytes,"media_type":media_type,"retention_seconds":mcloving_domain::artifacts::ARTIFACT_RETENTION_SECONDS})).await?;
            }
        }
        tx.commit().await?;
        Ok(())
    }
    /// Retire only stale hidden reservations. This is maintenance authority,
    /// not an agent bypass: an active current lease is never expired here.
    pub async fn expire_artifact_sets(&self, organization_id: Uuid) -> Result<(), StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
        // Own every candidate set before any short restore fence. Re-evaluate
        // the original exact expiry predicate only after that fence is held;
        // a current nonexpired lease cannot be retired by this ownership pass.
        sqlx::query("SELECT set_id FROM artifact_sets WHERE organization_id=$1 AND state='staging' ORDER BY attempt_id,fence FOR UPDATE")
            .bind(organization_id).fetch_all(&mut *tx).await?;
        acquire_restore_fence_shared(&mut tx).await?;
        sqlx::query("UPDATE artifact_sets s SET state='aborted' FROM attempts a WHERE s.organization_id=$1 AND s.state='staging' AND a.organization_id=s.organization_id AND a.id=s.attempt_id AND (a.fence<>s.fence OR a.restore_epoch<>s.restore_epoch OR a.restore_epoch<>(SELECT restore_epoch FROM controller_metadata WHERE singleton) OR a.status NOT IN ('accepted','running','finalizing','cancelling') OR a.lease_owner IS NULL OR a.lease_expires_at<=clock_timestamp())")
            .bind(organization_id).execute(&mut *tx).await?;
        sqlx::query("UPDATE attempt_objects o SET status='missing',checked_at=clock_timestamp() FROM artifact_sets s WHERE o.organization_id=$1 AND o.status='pending' AND o.artifact_set_id=s.set_id AND o.organization_id=s.organization_id AND o.attempt_id=s.attempt_id AND o.fence=s.fence AND s.state='aborted'")
            .bind(organization_id).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn abort_artifact_set(
        &self,
        a: &ArtifactSetAuthority,
        set_id: [u8; 32],
    ) -> Result<Vec<ArtifactSetMember>, StoreError> {
        let mut tx = self.tenant_transaction(a.organization_id).await?;
        attempt_lock(&mut tx, a).await?;
        let rows=sqlx::query_as::<_,(String,i64,String,Option<Vec<u8>>,Option<String>)>("SELECT name,bytes,media_type,object_digest,pending_token FROM artifact_set_members WHERE organization_id=$1 AND attempt_id=$2 AND fence=$3 AND set_id=$4 ORDER BY name FOR UPDATE")
            .bind(a.organization_id).bind(a.attempt_id).bind(a.fence).bind(set_id.as_slice()).fetch_all(&mut *tx).await?;
        let state=sqlx::query_scalar::<_,String>("SELECT state FROM artifact_sets WHERE organization_id=$1 AND attempt_id=$2 AND fence=$3 AND set_id=$4 FOR UPDATE")
            .bind(a.organization_id).bind(a.attempt_id).bind(a.fence).bind(set_id.as_slice()).fetch_optional(&mut *tx).await?;
        authorize(&mut tx, a, true).await?;
        if state.as_deref() == Some("available") {
            return Err(StoreError::InvalidObjectRecord(
                "committed artifact set cannot abort".into(),
            ));
        }
        sqlx::query("UPDATE artifact_sets SET state='aborted' WHERE organization_id=$1 AND attempt_id=$2 AND fence=$3 AND set_id=$4")
            .bind(a.organization_id).bind(a.attempt_id).bind(a.fence).bind(set_id.as_slice()).execute(&mut *tx).await?;
        sqlx::query("UPDATE attempt_objects SET status='missing',checked_at=clock_timestamp() WHERE organization_id=$1 AND attempt_id=$2 AND fence=$3 AND artifact_set_id=$4 AND status='pending'")
            .bind(a.organization_id).bind(a.attempt_id).bind(a.fence).bind(set_id.as_slice()).execute(&mut *tx).await?;
        tx.commit().await?;
        rows.into_iter()
            .map(|r| {
                Ok(ArtifactSetMember {
                    name: r.0,
                    bytes: r.1 as u64,
                    media_type: r.2,
                    digest: r.3.map(digest).transpose()?,
                    pending_token: r.4,
                })
            })
            .collect()
    }
}
impl ArtifactMemberClaim {
    pub async fn register(self, d: [u8; 32], token: &str) -> Result<(), StoreError> {
        self.register_inner(d, token, std::future::ready(())).await
    }
    /// Controlled real commit/result-loss boundary for debug integration drivers.
    /// The supplied future runs only AFTER PostgreSQL commit succeeds.
    #[cfg(debug_assertions)]
    pub async fn register_with_receipt_boundary(
        self,
        d: [u8; 32],
        token: &str,
        boundary: impl std::future::Future<Output = ()>,
    ) -> Result<(), StoreError> {
        self.register_inner(d, token, boundary).await
    }
    async fn register_inner(
        mut self,
        d: [u8; 32],
        token: &str,
        boundary: impl std::future::Future<Output = ()>,
    ) -> Result<(), StoreError> {
        let a = &self.authority;
        let state=sqlx::query_scalar::<_,String>("SELECT state FROM artifact_sets WHERE organization_id=$1 AND attempt_id=$2 AND fence=$3 AND set_id=$4 FOR SHARE")
            .bind(a.organization_id).bind(a.attempt_id).bind(a.fence).bind(self.set_id.as_slice()).fetch_one(&mut *self.tx).await?;
        authorize(&mut self.tx, a, false).await?;
        if state != "staging" && state != "available" {
            return Err(StoreError::InvalidObjectRecord(
                "artifact set aborted".into(),
            ));
        }
        acquire_object_deletion_fence(&mut self.tx, &d).await?;
        if let Some(existing) = self.member.digest {
            if existing != d || self.member.pending_token.as_deref() != Some(token) {
                return Err(StoreError::InvalidObjectRecord(
                    "artifact exact retry conflict".into(),
                ));
            }
        } else {
            let inserted=sqlx::query_scalar::<_,String>("INSERT INTO attempt_objects(organization_id,attempt_id,fence,kind,name,object_digest,bytes,media_type,status,artifact_set_id) VALUES($1,$2,$3,'artifact',$4,$5,$6,$7,'pending',$8) ON CONFLICT DO NOTHING RETURNING name")
                .bind(a.organization_id).bind(a.attempt_id).bind(a.fence).bind(&self.member.name).bind(d.as_slice()).bind(self.member.bytes as i64).bind(&self.member.media_type).bind(self.set_id.as_slice()).fetch_optional(&mut *self.tx).await?;
            if inserted.is_none() {
                return Err(StoreError::InvalidObjectRecord(
                    "artifact name already reserved".into(),
                ));
            }
            sqlx::query("UPDATE artifact_set_members SET object_digest=$6,pending_token=$7 WHERE organization_id=$1 AND attempt_id=$2 AND fence=$3 AND set_id=$4 AND name=$5")
                .bind(a.organization_id).bind(a.attempt_id).bind(a.fence).bind(self.set_id.as_slice()).bind(&self.member.name).bind(d.as_slice()).bind(token).execute(&mut *self.tx).await?;
            sqlx::query("INSERT INTO object_retention(organization_id,object_digest,retain_until) VALUES($1,$2,clock_timestamp()+interval '30 days') ON CONFLICT(organization_id,object_digest) DO UPDATE SET retain_until=GREATEST(object_retention.retain_until,EXCLUDED.retain_until),updated_at=clock_timestamp()")
                .bind(a.organization_id).bind(d.as_slice()).execute(&mut *self.tx).await?;
        }
        self.tx.commit().await?;
        boundary.await;
        Ok(())
    }
}
