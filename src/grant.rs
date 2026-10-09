//! Grant signing and verification: the identity's crypto side of the
//! per-document access model (the types and the access table live in
//! `craft_collab::grant`).
//!
//! A grant is signed by the host's identity key over its canonical JSON and
//! verified against the host's carried public key, so a holder can hold the
//! host to exactly what it was given, and a stranger cannot mint a grant.

use craft_collab::{Grant, SignedGrant};
use macula_rust::node_key::node_id_of;
use macula_rust::profile::Profile;

use crate::identity::Identity;

/// Signs `grant` as the host.
pub fn sign_grant(identity: &Identity, grant: &Grant) -> Result<SignedGrant, String> {
    let bytes = grant.signed_bytes()?;
    let signature = identity.sign(&bytes)?;
    Ok(SignedGrant {
        grant: grant.clone(),
        signature,
    })
}

/// Verifies `signed` against `host_carried_key`, at `now_ms`: the signature
/// must verify under that key, the key must derive the grant's host id, and
/// the grant must be live. The verifier is the caller holding the host's
/// carried key (from the invite or the document).
pub fn verify_grant(
    signed: &SignedGrant,
    host_carried_key: &[u8],
    profile: Profile,
    now_ms: u64,
) -> Result<Grant, String> {
    let bytes = signed.grant.signed_bytes()?;
    if !macula_rust::node_key::verify(&bytes, &signed.signature, host_carried_key, profile) {
        return Err("the grant's signature does not verify under the host key".into());
    }
    let host_id = node_id_of(host_carried_key, profile);
    let host_hex: String = host_id.iter().map(|b| format!("{b:02x}")).collect();
    if host_hex != signed.grant.host {
        return Err("the grant names a host that did not sign it".into());
    }
    if !signed.grant.is_live(now_ms) {
        return Err("the grant is not live".into());
    }
    Ok(signed.grant.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use craft_collab::Role;

    fn at(dir: &std::path::Path, slug: &str, name: &str) -> Identity {
        Identity::load_or_create_with(Profile::PqPure, slug, name, None, Some(dir))
            .expect("identity")
    }

    fn grant(host: &Identity, holder: &str) -> Grant {
        Grant {
            v: 1,
            doc: "demo".into(),
            host: host.node_id().to_string(),
            holder: holder.into(),
            role: Role::Editor,
            issued_ms: 100,
            expires_ms: 1_000,
            nonce: "n1".into(),
        }
    }

    #[test]
    fn a_grant_verifies_under_the_host_key_only() {
        let dir = tempfile::tempdir().expect("temp dir");
        let host = at(dir.path(), "host", "Host");
        let other = at(dir.path(), "other", "Other");
        let signed = sign_grant(&host, &grant(&host, "0011223344")).expect("sign");

        assert!(verify_grant(&signed, &host.carried_key(), Profile::PqPure, 500).is_ok());
        assert!(
            verify_grant(&signed, &other.carried_key(), Profile::PqPure, 500).is_err(),
            "another key does not verify it"
        );
        assert!(
            verify_grant(&signed, &host.carried_key(), Profile::PqPure, 5_000).is_err(),
            "expiry is enforced"
        );
    }

    #[test]
    fn a_tampered_grant_is_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        let host = at(dir.path(), "host", "Host");
        let signed = sign_grant(&host, &grant(&host, "0011223344")).expect("sign");

        let mut moved = signed.clone();
        moved.grant.holder = "0099887766".into();
        assert!(
            verify_grant(&moved, &host.carried_key(), Profile::PqPure, 500).is_err(),
            "the holder field is signed"
        );

        let mut loosened = signed.clone();
        loosened.grant.expires_ms = 1_000_000;
        assert!(
            verify_grant(&loosened, &host.carried_key(), Profile::PqPure, 500).is_err(),
            "the expiry is signed"
        );
    }
}
