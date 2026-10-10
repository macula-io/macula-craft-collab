//! Realm membership for Craft: the join-session (citizen) and silent
//! device-tier memberships, and the credential a confirmed one leaves
//! beside the identity keys.
//!
//! The credential's shape mirrors what macula-mcp stores and macula-realm
//! issues: node id, org identity, tier, the membership UCAN where the realm
//! minted one, and (citizen) the refresh token and cert.

pub mod proof;
pub mod session;

use std::path::PathBuf;

use macula_rust::pool::Pool;
use serde::{Deserialize, Serialize};

pub use proof::{
    DEVICE_REQUEST_TAG, DEVICE_REQUEST_VERSION, DeviceRequestProof, JOIN_SESSION_PROCEDURE, MEMBERSHIP_UCAN_PROCEDURE, PROOF_SKEW_MS, canonical_json,
    canonical_mesh, device_request_message, verify_device_request,
};
pub use session::{ConfirmedSession, CreatedSession, SessionStatus};

use crate::identity::Identity;

/// Which path bound this node to the realm: the silent device-tier proof, or
/// a person through the realm's join session. A citizen credential is
/// strictly stronger; nothing ever downgrades one to a device credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Device,
    Citizen,
}

/// A stored realm membership for one node.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RealmCredential {
    pub node_id: String,
    /// The realm's name (`io.macula`).
    pub realm: String,
    /// The realm service origin this credential was obtained from.
    pub portal: String,
    /// The org identity the realm reports (`mri:org:io.macula/<handle>`).
    pub org_identity: String,
    #[serde(default)]
    pub account: Option<String>,
    #[serde(default)]
    pub cert_pem: Option<String>,
    #[serde(default)]
    pub refresh_token: String,
    pub joined_at_ms: u64,
    /// This device's own node id, as the realm echoed it.
    #[serde(default)]
    pub citizen_did: Option<String>,
    /// The membership UCAN, where the realm mints one.
    #[serde(default)]
    pub ucan: Option<String>,
    pub tier: Tier,
}

impl RealmCredential {
    /// The org handle the realm reports (`rgfaber`), when there is one.
    pub fn handle(&self) -> Option<String> {
        handle_of(&self.org_identity)
    }

    /// When the membership UCAN expires, in milliseconds.
    pub fn ucan_expires_ms(&self) -> Option<u64> {
        self.ucan.as_deref().and_then(ucan_expiry_ms)
    }
}

/// `mri:org:io.macula/rgfaber` -> `rgfaber`; a device-tier org identity
/// (`mri:org:io.macula`, no person) has no handle. Pure.
pub fn handle_of(org_identity: &str) -> Option<String> {
    let (_, last) = org_identity.rsplit_once('/')?;
    if last.is_empty() { None } else { Some(last.to_string()) }
}

/// The realm id of a realm name: macula_realm's `id/1`, the sha256 of the
/// name's bytes.
pub fn realm_id_of(name: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(name.as_bytes()).into()
}

/// The membership UCAN's `exp` claim in milliseconds, from the JWT's payload.
/// Reads, never verifies: verification is `macula_rust::ucan`'s job.
pub fn ucan_expiry_ms(ucan: &str) -> Option<u64> {
    use base64::Engine as _;
    let payload = ucan.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    json.get("exp")?.as_u64().map(|s| s.saturating_mul(1_000))
}

/// Where realm credentials live for this data directory:
/// `<data>/craft/realm/<node_id>/<realm>.json`, beside the identity keys.
pub fn realm_dir() -> Option<PathBuf> {
    Some(crate::identity::craft_data_dir()?.join("craft").join("realm").to_path_buf())
}

fn credential_path(dir: &std::path::Path, node_id: &str, realm: &str) -> PathBuf {
    let safe = |s: &str| s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' { c } else { '_' }).collect::<String>();
    dir.join(safe(node_id)).join(format!("{}.json", safe(realm)))
}

/// Reads this node's stored credential for a realm, if any. A credential
/// naming another node is refused (an identity change is not a membership).
pub fn load_credential(node_id: &str, realm: &str) -> Option<RealmCredential> {
    let dir = realm_dir()?;
    load_credential_in(&dir, node_id, realm)
}

/// [`load_credential`] against an explicit directory (tests, custom setups).
pub fn load_credential_in(dir: &std::path::Path, node_id: &str, realm: &str) -> Option<RealmCredential> {
    let bytes = std::fs::read(credential_path(dir, node_id, realm)).ok()?;
    let cred: RealmCredential = serde_json::from_slice(&bytes).ok()?;
    (cred.node_id == node_id).then_some(cred)
}

/// Writes a credential beside the keys, owner-only, and returns its path.
pub fn store_credential(cred: &RealmCredential) -> Result<PathBuf, String> {
    let dir = realm_dir().ok_or_else(|| "no per-user data directory for realm credentials".to_string())?;
    store_credential_in(&dir, cred)
}

/// [`store_credential`] against an explicit directory.
pub fn store_credential_in(dir: &std::path::Path, cred: &RealmCredential) -> Result<PathBuf, String> {
    let path = credential_path(dir, &cred.node_id, &cred.realm);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        secure_dir(parent);
    }
    let bytes = serde_json::to_vec_pretty(cred).map_err(|e| e.to_string())?;
    std::fs::write(&path, bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    secure_file(&path);
    Ok(path)
}

/// Every confirmed membership this node holds, for `mesh_list_realms`-style
/// reads.
pub fn list_credentials(node_id: &str) -> Vec<RealmCredential> {
    let Some(dir) = realm_dir() else {
        return Vec::new();
    };
    let realm_dir = dir.join(node_id);
    let Ok(entries) = std::fs::read_dir(&realm_dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(cred) = serde_json::from_slice::<RealmCredential>(&bytes) else {
            continue;
        };
        if cred.node_id == node_id {
            out.push(cred);
        }
    }
    out.sort_by(|a, b| a.realm.cmp(&b.realm));
    out
}

#[cfg(unix)]
fn secure_dir(dir: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn secure_dir(_dir: &std::path::Path) {}

#[cfg(unix)]
fn secure_file(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn secure_file(_path: &std::path::Path) {}

/// Which realm the silent device-tier auto-join targets, when the feature
/// is on (`MACULA_CRAFT_AUTOJOIN_REALM`, e.g. `io.macula`). Unset means the
/// feature does nothing — the same opt-in rollout macula-mcp uses.
pub fn auto_join_realm() -> Option<String> {
    std::env::var("MACULA_CRAFT_AUTOJOIN_REALM").ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// The `can` a realm mints for a device-bound membership, and the one a
/// person's confirmation mints.
pub const MEMBER_DEVICE_CAN: &str = "member/device-verified";
pub const MEMBER_CITIZEN_CAN: &str = "member/email-verified";

/// How close to expiry a device-tier membership is re-minted, on connect.
pub const RENEW_MARGIN_MS: u64 = 30 * 60 * 1_000;

/// Verifies a membership UCAN the way a host does when a peer presents it:
/// issued by the realm's own key, audience = the verified caller (exactly
/// the presenting node), a member capability on this realm. `authorize`
/// checks the audience itself, so a token that names anyone else is
/// refused; the capability check pins the realm and the `can`.
pub fn verify_membership(ucan: &str, realm_key: &[u8], realm_name: &str, node_id: &str, now_s: i64) -> Result<(), String> {
    let caller: [u8; 32] =
        hex::decode(node_id).map_err(|e| format!("node id: {e}"))?.try_into().map_err(|_| "node id is not 32 bytes".to_string())?;
    let realm_with = format!("mri:realm:{realm_name}");
    let key_id = macula_rust::node_key::key_id_of(realm_key, macula_rust::profile::Profile::PqHybrid);
    for can in [MEMBER_DEVICE_CAN, MEMBER_CITIZEN_CAN] {
        let policy = macula_rust::ucan::Policy::RealmMemberRequired { key_id, can: can.to_string() };
        let ctx = macula_rust::ucan::Context {
            caller,
            profile: macula_rust::profile::Profile::PqHybrid,
            now: now_s,
            request: None,
            proofs: std::collections::HashMap::new(),
        };
        if let Ok(claims) = macula_rust::ucan::authorize(ucan.as_bytes(), &policy, &ctx)
            && capability_covers(&claims, &realm_with, can)
        {
            return Ok(());
        }
    }
    Err("not a member of this realm, or the token is not this node's".into())
}

/// Whether any capability entry names exactly this realm and this `can`.
fn capability_covers(claims: &serde_json::Map<String, serde_json::Value>, realm_with: &str, can: &str) -> bool {
    let Some(caps) = claims.get("cap").and_then(|v| v.as_array()) else {
        return false;
    };
    caps.iter().any(|entry| entry.get("with").and_then(|v| v.as_str()) == Some(realm_with) && entry.get("can").and_then(|v| v.as_str()) == Some(can))
}

/// Whether this credential's membership should be re-minted. A citizen
/// credential is a person's binding and is never silently re-minted (its
/// renewal is the portal's session); a device credential is re-minted when
/// its UCAN is missing or inside the renewal margin.
pub fn needs_renewal(cred: &RealmCredential, now_ms: u64) -> bool {
    match cred.tier {
        Tier::Citizen => false,
        Tier::Device => match cred.ucan_expires_ms() {
            None => true,
            Some(expires) => expires <= now_ms.saturating_add(RENEW_MARGIN_MS),
        },
    }
}

/// Re-mints a device-tier membership (a fresh proof, the realm's newest
/// UCAN) and stores it. A citizen credential is returned untouched: a
/// silent re-mint must never downgrade a person's binding.
pub async fn renew_membership(pool: &Pool, identity: &Identity, realm_name: &str, now_ms: u64) -> Result<RealmCredential, String> {
    if let Some(cred) = load_credential(identity.node_id(), realm_name)
        && cred.tier == Tier::Citizen
    {
        return Ok(cred);
    }
    let cred = join_device(pool, identity, realm_name, now_ms).await?;
    store_credential(&cred)?;
    Ok(cred)
}

/// The seam's membership verifier over a realm's UCANs: what a host runs
/// when a document is shared with a realm. It holds the realm's pinned key
/// and the role members are admitted with; nothing about a presented token
/// is trusted beyond the realm's own signature and the audience check.
pub struct RealmMemberVerifier {
    realm: String,
    realm_key: Vec<u8>,
    role: craft_collab::Role,
}

impl RealmMemberVerifier {
    pub fn new(realm: &str, realm_key: Vec<u8>, role: craft_collab::Role) -> Self {
        RealmMemberVerifier { realm: realm.to_string(), realm_key, role }
    }
}

impl craft_collab::MembershipVerifier for RealmMemberVerifier {
    fn verify_member(&self, ucan: &str, node_id: &str, now_ms: u64) -> Result<(), String> {
        verify_membership(ucan, &self.realm_key, &self.realm, node_id, (now_ms / 1_000) as i64)
    }

    fn role(&self) -> craft_collab::Role {
        self.role
    }
}

/// The realm's membership-minting procedure, realm-name-prefixed the way a
/// procedure advertisement carries it.
pub fn membership_ucan_procedure(realm_name: &str) -> String {
    format!("{realm_name}/_realm/_realm/identity/issue_membership_ucan_v1")
}

/// A text field of a reply, unwrapping macula-realm's double-hex encoding of
/// text values (`"0x" + hex(utf8)`; a bare binary arrives as `0x` hex) and
/// accepting a plain text or raw-bytes reply unchanged.
pub fn unwrap_text_field(value: &macula_rust::cbor::Value) -> Option<String> {
    use macula_rust::cbor::Value;
    match value {
        Value::Text(t) => {
            if let Some(hex) = t.strip_prefix("0x") {
                let bytes = hex::decode(hex).ok()?;
                String::from_utf8(bytes).ok()
            } else {
                Some(t.clone())
            }
        }
        Value::Bytes(b) => String::from_utf8(b.clone()).ok(),
        _ => None,
    }
}

/// One silent device-tier auto-join: proves this node's key for the
/// membership call and returns the credential it earns, without storing it.
/// A reply naming another node is refused.
pub async fn join_device(pool: &Pool, identity: &Identity, realm_name: &str, now_ms: u64) -> Result<RealmCredential, String> {
    use base64::Engine as _;
    use macula_rust::cbor::Value;

    let realm_id = realm_id_of(realm_name);
    let public_key = base64::engine::general_purpose::STANDARD.encode(identity.carried_key());
    let request = Value::Map(vec![(Value::text("public_key"), Value::text(public_key.clone()))]);
    let proof = identity.device_request_proof(&realm_id, MEMBERSHIP_UCAN_PROCEDURE, &request, now_ms)?;
    let payload = Value::Map(vec![(Value::text("public_key"), Value::text(public_key)), (Value::text("proof"), proof.to_cbor())]);
    let call = macula_rust::pool::Call {
        realm: realm_id,
        procedure: membership_ucan_procedure(realm_name),
        provider: [0; 32],
        payload,
        timeout: std::time::Duration::from_secs(8),
        token: None,
        proofs: Vec::new(),
        confidential: Default::default(),
    };
    let reply = pool.call(call).await.map_err(|e| format!("issue_membership_ucan: {e:?}"))?;
    let citizen_did = reply.get("citizen_did").and_then(unwrap_text_field);
    let ucan = reply.get("ucan").and_then(unwrap_text_field);
    if let Some(error) = reply.get("error").and_then(unwrap_text_field) {
        return Err(format!("issue_membership_ucan refused: {error}"));
    }
    let (Some(citizen_did), Some(ucan)) = (citizen_did, ucan) else {
        return Err(format!("issue_membership_ucan returned an unexpected shape: {reply:?}"));
    };
    if !citizen_did.eq_ignore_ascii_case(identity.node_id()) {
        return Err(format!("issue_membership_ucan names {citizen_did}, not this node {}", identity.node_id()));
    }
    Ok(RealmCredential {
        node_id: identity.node_id().to_string(),
        realm: realm_name.to_string(),
        portal: realm_name.to_string(),
        org_identity: format!("mri:org:{realm_name}"),
        account: None,
        cert_pem: None,
        refresh_token: String::new(),
        joined_at_ms: now_ms,
        citizen_did: Some(citizen_did),
        ucan: Some(ucan),
        tier: Tier::Device,
    })
}

/// The idempotent, non-fatal entry point, called on connect: no-op when the
/// feature is off or this node already holds ANY credential for the realm
/// (never downgrade or duplicate); a failure is logged and never takes the
/// connection down.
pub async fn ensure_auto_join(pool: &Pool, identity: &Identity, now_ms: u64) {
    let Some(realm_name) = auto_join_realm() else {
        return;
    };
    if let Some(cred) = load_credential(identity.node_id(), &realm_name)
        && !needs_renewal(&cred, now_ms)
    {
        return;
    }
    match join_device(pool, identity, &realm_name, now_ms).await {
        Ok(cred) => {
            if let Err(e) = store_credential(&cred) {
                log_stderr(&format!("realm auto-join: storing the credential failed: {e}"));
            }
        }
        Err(e) => log_stderr(&format!("realm auto-join of {} against {realm_name} failed: {e}", identity.node_id())),
    }
}

fn log_stderr(message: &str) {
    eprintln!("{message}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_realm_id_is_the_sha256_of_the_name() {
        assert_eq!(hex::encode(realm_id_of("io.macula")), "abb81b5a614b63551b400b810648c0c8a78efad845442630c94b46cc95d2fcd1");
    }

    #[test]
    fn handles_and_expiry_read_the_way_the_realm_writes_them() {
        assert_eq!(handle_of("mri:org:io.macula/rgfaber").as_deref(), Some("rgfaber"));
        assert_eq!(handle_of("mri:org:io.macula/"), None);
        assert_eq!(handle_of("mri:org:io.macula"), None, "a device-tier org identity has no person");
        let ucan = "eyJhbGciOiJFUzI1NiJ9.eyJleHAiOjE3OTIwMDAwMDAsImNhbiI6InJlYWxtL21lbWJlciJ9.sig";
        assert_eq!(ucan_expiry_ms(ucan), Some(1_792_000_000_000));
        assert_eq!(ucan_expiry_ms("not-a-jwt"), None);
    }

    #[test]
    fn a_membership_ucan_verifies_only_for_its_audience_realm_and_key() {
        use macula_rust::node_key::{NodeKey, PUZZLE_DIFFICULTY};
        use macula_rust::profile::Profile;
        use macula_rust::ucan::{Capability, Options, create};

        let realm_key = NodeKey::generate_identity(Profile::PqHybrid, PUZZLE_DIFFICULTY).expect("realm key");
        let member = NodeKey::generate_identity(Profile::PqHybrid, PUZZLE_DIFFICULTY).expect("member key");
        let audience = member.node_id().expect("node id");
        let now_s = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock").as_secs() as i64;
        let mint = |can: &str, with: &str| {
            let token = create(
                &realm_key,
                &audience,
                &[Capability { with: with.into(), can: can.into() }],
                &Options { exp: now_s + 3_600, ..Options::default() },
            )
            .expect("mint");
            String::from_utf8(token).expect("jwt text")
        };
        let token = mint(MEMBER_DEVICE_CAN, "mri:realm:io.macula");
        let node_hex = hex::encode(audience);
        verify_membership(&token, &realm_key.public_key(), "io.macula", &node_hex, now_s).expect("its own audience and realm verify");
        assert!(
            verify_membership(&token, &realm_key.public_key(), "io.macula", &hex::encode([9u8; 32]), now_s).is_err(),
            "another node's claims are refused"
        );
        let other_realm_key = NodeKey::generate_identity(Profile::PqHybrid, PUZZLE_DIFFICULTY).expect("other key");
        assert!(
            verify_membership(&token, &other_realm_key.public_key(), "io.macula", &node_hex, now_s).is_err(),
            "another key's realm does not vouch"
        );
        assert!(verify_membership(&token, &realm_key.public_key(), "net.other", &node_hex, now_s).is_err(), "another realm does not match");
        let wrong_can = mint("member/something-else", "mri:realm:io.macula");
        assert!(verify_membership(&wrong_can, &realm_key.public_key(), "io.macula", &node_hex, now_s).is_err(), "a non-member capability is refused");
    }

    #[test]
    fn the_seam_verifier_admits_members_of_its_own_realm() {
        use craft_collab::MembershipVerifier as _;
        use macula_rust::node_key::{NodeKey, PUZZLE_DIFFICULTY};
        use macula_rust::profile::Profile;
        use macula_rust::ucan::{Capability, Options, create};

        let realm_key = NodeKey::generate_identity(Profile::PqHybrid, PUZZLE_DIFFICULTY).expect("realm key");
        let member = NodeKey::generate_identity(Profile::PqHybrid, PUZZLE_DIFFICULTY).expect("member key");
        let audience = member.node_id().expect("node id");
        let now_s = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock").as_secs() as i64;
        let token = create(
            &realm_key,
            &audience,
            &[Capability { with: "mri:realm:io.macula".into(), can: MEMBER_DEVICE_CAN.into() }],
            &Options { exp: now_s + 3_600, ..Options::default() },
        )
        .expect("mint");
        let token = String::from_utf8(token).expect("jwt");
        let node_hex = hex::encode(audience);

        let verifier = RealmMemberVerifier::new("io.macula", realm_key.public_key(), craft_collab::Role::Editor);
        assert_eq!(verifier.role(), craft_collab::Role::Editor);
        let now_ms = (now_s as u64) * 1_000;
        verifier.verify_member(&token, &node_hex, now_ms).expect("its own member verifies");
        assert!(verifier.verify_member(&token, &hex::encode([9u8; 32]), now_ms).is_err(), "another node's token is not a membership for this caller");
        assert!(verifier.verify_member("not-a-jwt", &node_hex, now_ms).is_err());
    }

    #[test]
    fn renewal_decision_follows_tier_and_expiry() {
        use base64::Engine as _;
        let fake_ucan = |exp_s: u64| {
            let payload = serde_json::json!({"exp": exp_s}).to_string();
            format!("h.{}.s", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload))
        };
        let cred = |tier: Tier, ucan: Option<String>| RealmCredential {
            node_id: "0011".into(),
            realm: "io.macula".into(),
            portal: "io.macula".into(),
            org_identity: "mri:org:io.macula".into(),
            account: None,
            cert_pem: None,
            refresh_token: String::new(),
            joined_at_ms: 0,
            citizen_did: None,
            ucan,
            tier,
        };
        let now = 1_000_000u64;
        assert!(!needs_renewal(&cred(Tier::Device, Some(fake_ucan(now / 1000 + 4 * 3600))), now), "a fresh device UCAN is left alone");
        assert!(needs_renewal(&cred(Tier::Device, Some(fake_ucan(now / 1000 + 600))), now), "inside the margin it renews");
        assert!(needs_renewal(&cred(Tier::Device, None), now), "a device credential without a UCAN renews");
        assert!(!needs_renewal(&cred(Tier::Citizen, Some(fake_ucan(now / 1000 + 60))), now), "a person's binding is never silently re-minted");
    }

    #[test]
    fn credentials_round_trip_owner_only() {
        let dir = tempfile::tempdir().expect("temp dir");
        let cred = RealmCredential {
            node_id: "0011".into(),
            realm: "io.macula".into(),
            portal: "io.macula".into(),
            org_identity: "mri:org:io.macula/rgfaber".into(),
            account: Some("raf@example.com".into()),
            cert_pem: None,
            refresh_token: "rt".into(),
            joined_at_ms: 1_000,
            citizen_did: Some("0011".into()),
            ucan: None,
            tier: Tier::Citizen,
        };
        let path = store_credential_in(dir.path(), &cred).expect("store");
        assert_eq!(load_credential_in(dir.path(), "0011", "io.macula").as_ref(), Some(&cred));
        assert_eq!(load_credential_in(dir.path(), "0022", "io.macula"), None, "another node reads nothing");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "the credential is owner-readable only");
        }
    }
}
