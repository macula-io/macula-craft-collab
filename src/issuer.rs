//! The host side's signing: minting grants, revocations, group credentials
//! and open tokens from the identity key, as the seam's [`GrantIssuer`].

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use craft_collab::{GRANT_VERSION, Grant, GrantIssuer, Revocation, Role, SignedGrant, SignedRevocation, mint_nonce};
use macula_rust::node_key::NodeKey;
use macula_rust::ucan::{self, Capability, Options as UcanOptions};

use crate::identity::Identity;
use crate::roster::Roster;

/// The host's identity as a grant issuer.
pub struct IdentityIssuer {
    identity: Identity,
    /// The host's own record of what it decided, when it keeps one: every
    /// grant, revocation and invite minted here is written to it, and the key
    /// distributor this host serves answers from it.
    roster: Option<Arc<Roster>>,
}

impl IdentityIssuer {
    pub fn new(identity: Identity) -> Self {
        IdentityIssuer { identity, roster: None }
    }

    /// The same issuer, recording every decision it makes in `roster`: what a
    /// host that serves its share's key distributor needs.
    pub fn with_roster(mut self, roster: Arc<Roster>) -> Self {
        self.roster = Some(roster);
        self
    }

    /// The host id this issuer signs as.
    pub fn node_id(&self) -> &str {
        self.identity.node_id()
    }

    fn signed_revocation(&self, revocation: &Revocation) -> Result<SignedRevocation, String> {
        let bytes = revocation.signed_bytes()?;
        let signature = self.identity.sign(&bytes)?;
        Ok(SignedRevocation { revocation: revocation.clone(), signature })
    }
}

/// The credential a holder presents to pull the key of the sealed group
/// `group`: a UCAN for the host's own `<org>/group_keys_v1`, minted by the
/// host's key as that org, bound to `audience` — the mesh checks a UCAN's
/// audience against the caller, so the credential is the invitation — and
/// valid for `ttl_ms` from `now_ms`, never longer.
pub(crate) fn group_ucan(key: &NodeKey, realm: &str, org: &str, audience: &[u8; 32], ttl_ms: u64, now_ms: u64) -> Result<String, String> {
    let exp =
        i64::try_from(now_ms.saturating_add(ttl_ms).div_ceil(1_000)).map_err(|_| "the group credential's expiry is out of range".to_string())?;
    let caps = [Capability { with: format!("mri:org:{realm}/{org}"), can: macula_rust::group::GROUP_KEYS_CAN.to_string() }];
    let token = ucan::create(key, audience, &caps, &UcanOptions { exp, ..Default::default() }).map_err(|e| format!("the group credential: {e}"))?;
    String::from_utf8(token).map_err(|_| "the group credential is not text".to_string())
}

/// A group prefix's realm name and org: `<realm>/<org>/...`.
fn realm_and_org(group: &str) -> Result<(&str, &str), String> {
    let mut segments = group.split('/');
    match (segments.next(), segments.next()) {
        (Some(realm), Some(org)) if !realm.is_empty() && !org.is_empty() => Ok((realm, org)),
        _ => Err("a sealed group's prefix names a realm and an org".into()),
    }
}

/// A per-process salt so two grants minted in one millisecond differ.
fn salt() -> u32 {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    (std::process::id().wrapping_mul(2_654_435_761)) ^ n
}

impl GrantIssuer for IdentityIssuer {
    fn node_id(&self) -> String {
        self.identity.node_id().to_string()
    }

    fn carried_key(&self) -> Vec<u8> {
        self.identity.carried_key()
    }

    fn issue(&self, doc: &str, holder: &str, role: Role, ttl_ms: u64, now_ms: u64) -> Result<SignedGrant, String> {
        let grant = Grant {
            v: GRANT_VERSION,
            doc: doc.to_string(),
            host: self.identity.node_id().to_string(),
            holder: holder.to_string(),
            role,
            issued_ms: now_ms,
            expires_ms: now_ms.saturating_add(ttl_ms),
            nonce: mint_nonce(now_ms, salt()),
        };
        let signed = crate::grant::sign_grant(&self.identity, &grant)?;
        if let Some(roster) = &self.roster {
            roster.note_grant(holder, grant.issued_ms, grant.expires_ms);
        }
        Ok(signed)
    }

    fn revoke(&self, doc: &str, holder: &str, now_ms: u64) -> Result<SignedRevocation, String> {
        let revocation = Revocation {
            v: GRANT_VERSION,
            doc: doc.to_string(),
            host: self.identity.node_id().to_string(),
            holder: holder.to_string(),
            issued_ms: now_ms,
            nonce: mint_nonce(now_ms, salt()),
        };
        let signed = self.signed_revocation(&revocation)?;
        if let Some(roster) = &self.roster {
            roster.note_revocation(holder, revocation.issued_ms);
        }
        Ok(signed)
    }

    fn open_token(&self, doc: &str, role: Role, ttl_ms: u64, now_ms: u64) -> Result<SignedGrant, String> {
        self.issue(doc, "", role, ttl_ms, now_ms)
    }

    /// The invitee's credential for the share group's key. A sealed share is
    /// shared with named people, one invite each: an open invite has no node
    /// to bind this to, and macula-rust checks a UCAN's audience against the
    /// caller, so it is refused here rather than minted into a line anyone
    /// could use.
    fn group_grant(&self, _doc: &str, group: &str, holder: Option<&str>, ttl_ms: u64, now_ms: u64) -> Result<String, String> {
        let Some(holder) = holder else {
            return Err("an open invite cannot be sealed: invite people by name".into());
        };
        let (realm, org) = realm_and_org(group)?;
        let own = format!("~{}", self.identity.node_id());
        if org != own {
            return Err(format!("this host does not serve {org}: its own share groups are under {own}"));
        }
        let audience: [u8; 32] = crate::hex_bytes(holder)?.try_into().map_err(|_| "an invitee's node id is 32 bytes".to_string())?;
        let credential = group_ucan(&self.identity.key(), realm, org, &audience, ttl_ms, now_ms)?;
        if let Some(roster) = &self.roster {
            roster.note_invite(holder, now_ms.saturating_add(ttl_ms));
        }
        Ok(credential)
    }

    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        self.identity.sign(bytes)
    }
}

/// Verifies an invite envelope's host signature: the signature must verify
/// under the envelope's own carried key (that is the anchor), the host id
/// must be the one that key names, and the version must be current. This is
/// what a joiner checks before it connects anywhere.
pub fn verify_invite(invite: &craft_collab::Invite) -> Result<(), String> {
    if invite.v != craft_collab::INVITE_VERSION {
        return Err(format!("unsupported invite version {}", invite.v));
    }
    if invite.signature.is_empty() {
        return Err("the invite is not signed".into());
    }
    let key = hex_bytes(&invite.host_key)?;
    let profile = macula_rust::profile::Profile::parse(&invite.profile).map_err(|e| format!("profile: {e}"))?;
    let bytes = invite.signed_bytes()?;
    if !macula_rust::node_key::verify(&bytes, &invite.signature, &key, profile) {
        return Err("the invite's signature does not verify under its host key".into());
    }
    let host_id = macula_rust::node_key::node_id_of(&key, profile);
    let host_hex: String = host_id.iter().map(|b| format!("{b:02x}")).collect();
    if host_hex != invite.host {
        return Err("the invite names a host that did not sign it".into());
    }
    Ok(())
}

fn hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("an odd number of hex digits".into());
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use craft_collab::GrantVerifier;
    use macula_rust::profile::Profile;

    fn identity(dir: &std::path::Path, slug: &str) -> Identity {
        Identity::load_or_create_with(Profile::PqPure, slug, "Host", None, Some(dir)).expect("identity")
    }

    #[test]
    fn invites_verify_only_when_signed_by_the_named_host() {
        use craft_collab::{INVITE_VERSION, Invite};

        let dir = tempfile::tempdir().expect("temp dir");
        let id = identity(dir.path(), "host");
        let issuer = IdentityIssuer::new(id.clone());
        let token = issuer.open_token("demo", Role::Editor, 60_000, 1_000).expect("token");
        let mut invite = Invite {
            v: INVITE_VERSION,
            doc: "demo".into(),
            host: id.node_id().to_string(),
            host_key: id.carried_key().iter().map(|b| format!("{b:02x}")).collect(),
            host_name: "Host".into(),
            realm: "aa".repeat(32),
            realm_key: String::new(),
            profile: "pq_pure".into(),
            seed: "station.example:4433:bb".to_string(),
            issued_ms: 1_000,
            expires_ms: 61_000,
            token: Some(token),
            member_role: None,
            member_realm: None,
            host_realm: None,
            invitee: None,
            invitee_name: None,
            group: "io.macula/~aa/craft/9f9f9f9f".into(),
            group_grant: "ucan-for-the-group".into(),
            signature: Vec::new(),
        };
        assert!(verify_invite(&invite).is_err(), "unsigned is refused");

        invite.signature = issuer.sign(&invite.signed_bytes().expect("bytes")).expect("sign");
        verify_invite(&invite).expect("a properly signed invite verifies");

        // A swapped seed (a redirected joiner) breaks the signature.
        let mut tampered = invite.clone();
        tampered.seed = "evil.example:4433:cc".to_string();
        assert!(verify_invite(&tampered).is_err(), "the seed is covered by the signature");

        // A swapped token breaks it too.
        let mut tampered = invite.clone();
        tampered.token.as_mut().expect("token").signature.push(9);
        assert!(verify_invite(&tampered).is_err(), "the token is covered");

        // Signing with another identity does not pass as the named host.
        let attacker = identity(dir.path(), "attacker");
        let mut forged = invite.clone();
        forged.signature = IdentityIssuer::new(attacker).sign(&forged.signed_bytes().expect("bytes")).expect("sign");
        assert!(verify_invite(&forged).is_err(), "another key does not vouch for this host");
    }

    #[test]
    fn the_issuer_mints_verifiable_grants_revocations_and_tokens() {
        let dir = tempfile::tempdir().expect("temp dir");
        let id = identity(dir.path(), "host");
        let issuer = IdentityIssuer::new(id.clone());
        let verifier = crate::grant::KeyGrantVerifier::new(id.carried_key(), Profile::PqPure);

        let grant = issuer.issue("demo", "0011", Role::Editor, 60_000, 1_000).expect("issue");
        let verified = verifier.verify(&grant, 1_500).expect("verifies");
        assert_eq!(verified.holder, "0011");
        assert_eq!(verified.expires_ms, 61_000);
        assert!(verified.nonce.starts_with(&format!("{:016x}", 1_000)), "nonce is sortable by time");

        let revocation = issuer.revoke("demo", "0011", 2_000).expect("revoke");
        let verified = verifier.verify_revocation(&revocation, 2_500).expect("verifies");
        assert_eq!(verified.holder, "0011");

        let token = issuer.open_token("demo", Role::Viewer, 60_000, 3_000).expect("token");
        let verified = verifier.verify(&token, 3_500).expect("token verifies");
        assert!(verified.is_open());
        assert_eq!(verified.role, Role::Viewer);
    }

    /// The claims of a UCAN, to check what a credential carries without
    /// trusting this crate's own reading of it.
    fn claims(token: &str) -> serde_json::Value {
        use base64::Engine as _;
        let body = token.split('.').nth(1).expect("a UCAN's claims");
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(body).expect("base64url");
        serde_json::from_slice(&raw).expect("claims JSON")
    }

    /// The group credential is the host's own distributor's: the org is this
    /// node, the capability is `group_keys`, the audience is the invitee, and
    /// it never outlives the invite it travels with.
    #[test]
    fn the_group_credential_is_bound_to_its_invitee_and_to_its_invite() {
        let dir = tempfile::tempdir().expect("temp dir");
        let id = identity(dir.path(), "host");
        let host = id.node_id().to_string();
        let group = format!("io.macula/~{host}/craft/0123456789abcdef0123456789abcdef");
        let invitee = "bb".repeat(32);
        let issuer = IdentityIssuer::new(id.clone());

        let credential = issuer.group_grant("demo", &group, Some(&invitee), 60_000, 1_000).expect("a credential");
        let claims = claims(&credential);
        assert_eq!(claims["aud"], serde_json::json!(invitee), "bound to the invitee");
        assert_eq!(
            claims["cap"],
            serde_json::json!([{"with": format!("mri:org:io.macula/~{host}"), "can": "group_keys"}]),
            "the host's own org, for group keys"
        );
        assert_eq!(claims["exp"], serde_json::json!(61), "the invite's lifetime, in seconds");
        assert_eq!(claims["iss"].as_str().map(|iss| iss.starts_with("did:")), Some(true), "signed by the host's key");
    }

    /// A sealed share is shared with named people: an open invite has no node
    /// to bind a credential to, and is refused rather than minted.
    #[test]
    fn an_open_invite_is_never_given_a_group_credential() {
        let dir = tempfile::tempdir().expect("temp dir");
        let id = identity(dir.path(), "host");
        let group = format!("io.macula/~{}/craft/0123456789abcdef0123456789abcdef", id.node_id());
        let issuer = IdentityIssuer::new(id.clone());
        assert!(issuer.group_grant("demo", &group, None, 60_000, 1_000).is_err());
    }

    /// A credential is never minted for a group another node's namespace owns:
    /// this host distributes its own share's keys and no one else's.
    #[test]
    fn a_group_under_another_org_is_not_this_hosts_to_mint_for() {
        let dir = tempfile::tempdir().expect("temp dir");
        let id = identity(dir.path(), "host");
        let other = format!("io.macula/~{}/craft/0123456789abcdef0123456789abcdef", "bb".repeat(32));
        let issuer = IdentityIssuer::new(id.clone());
        let err = issuer.group_grant("demo", &other, Some(&"cc".repeat(32)), 60_000, 1_000).expect_err("refused");
        assert!(err.contains("does not serve"), "{err}");
    }

    /// Every decision the issuer makes reaches the host's admission record,
    /// which is what the distributor it serves answers from.
    #[test]
    fn the_issuer_records_what_the_distributor_answers() {
        use crate::Roster;
        use macula_rust::group::Membership;

        let dir = tempfile::tempdir().expect("temp dir");
        let id = identity(dir.path(), "host");
        let node = format!("io.macula/~{}/craft/0123456789abcdef0123456789abcdef", id.node_id());
        let roster = Roster::new(id.node_id()).expect("a roster");
        let issuer = IdentityIssuer::new(id.clone()).with_roster(roster.clone());
        let invitee = "bb".repeat(32);
        let invitee_id: [u8; 32] = crate::hex_bytes(&invitee).expect("hex").try_into().expect("32");
        let now = craft_collab::now_ms();

        issuer.group_grant("demo", &node, Some(&invitee), 60_000, now).expect("a credential");
        assert_eq!(roster.membership(&node, invitee_id, now), Membership::In, "an invite is a reader");

        issuer.revoke("demo", &invitee, now + 1).expect("revoked");
        assert_eq!(roster.membership(&node, invitee_id, now + 2), Membership::NotAMember);
        assert!(roster.removed(&node, invitee_id), "and stays removed until a newer grant");

        issuer.issue("demo", &invitee, Role::Editor, 60_000, now + 3).expect("granted");
        assert_eq!(roster.membership(&node, invitee_id, now + 4), Membership::In, "a newer grant is the yes");
        assert!(!roster.removed(&node, invitee_id));
    }
}
