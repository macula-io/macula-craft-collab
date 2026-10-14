//! The host side's signing: minting grants, revocations and open tokens
//! from the identity key, as the seam's [`GrantIssuer`].

use std::sync::atomic::{AtomicU32, Ordering};

use craft_collab::{GRANT_VERSION, Grant, GrantIssuer, Revocation, Role, SignedGrant, SignedRevocation, mint_nonce};

use crate::identity::Identity;

/// The host's identity as a grant issuer.
pub struct IdentityIssuer {
    identity: Identity,
}

impl IdentityIssuer {
    pub fn new(identity: Identity) -> Self {
        IdentityIssuer { identity }
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
        crate::grant::sign_grant(&self.identity, &grant)
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
        self.signed_revocation(&revocation)
    }

    fn open_token(&self, doc: &str, role: Role, ttl_ms: u64, now_ms: u64) -> Result<SignedGrant, String> {
        self.issue(doc, "", role, ttl_ms, now_ms)
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
}
