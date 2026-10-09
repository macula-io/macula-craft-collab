//! The host side's signing: minting grants, revocations and open tokens
//! from the identity key, as the seam's [`GrantIssuer`].

use std::sync::atomic::{AtomicU32, Ordering};

use craft_collab::{
    GRANT_VERSION, Grant, GrantIssuer, Revocation, Role, SignedGrant, SignedRevocation, mint_nonce,
};

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
        Ok(SignedRevocation {
            revocation: revocation.clone(),
            signature,
        })
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

    fn issue(
        &self,
        doc: &str,
        holder: &str,
        role: Role,
        ttl_ms: u64,
        now_ms: u64,
    ) -> Result<SignedGrant, String> {
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

    fn open_token(
        &self,
        doc: &str,
        role: Role,
        ttl_ms: u64,
        now_ms: u64,
    ) -> Result<SignedGrant, String> {
        self.issue(doc, "", role, ttl_ms, now_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use craft_collab::GrantVerifier;
    use macula_rust::profile::Profile;

    fn identity(dir: &std::path::Path, slug: &str) -> Identity {
        Identity::load_or_create_with(Profile::PqPure, slug, "Host", None, Some(dir))
            .expect("identity")
    }

    #[test]
    fn the_issuer_mints_verifiable_grants_revocations_and_tokens() {
        let dir = tempfile::tempdir().expect("temp dir");
        let id = identity(dir.path(), "host");
        let issuer = IdentityIssuer::new(id.clone());
        let verifier = crate::grant::KeyGrantVerifier::new(id.carried_key(), Profile::PqPure);

        let grant = issuer
            .issue("demo", "0011", Role::Editor, 60_000, 1_000)
            .expect("issue");
        let verified = verifier.verify(&grant, 1_500).expect("verifies");
        assert_eq!(verified.holder, "0011");
        assert_eq!(verified.expires_ms, 61_000);
        assert!(
            verified.nonce.starts_with(&format!("{:016x}", 1_000)),
            "nonce is sortable by time"
        );

        let revocation = issuer.revoke("demo", "0011", 2_000).expect("revoke");
        let verified = verifier
            .verify_revocation(&revocation, 2_500)
            .expect("verifies");
        assert_eq!(verified.holder, "0011");

        let token = issuer
            .open_token("demo", Role::Viewer, 60_000, 3_000)
            .expect("token");
        let verified = verifier.verify(&token, 3_500).expect("token verifies");
        assert!(verified.is_open());
        assert_eq!(verified.role, Role::Viewer);
    }
}
