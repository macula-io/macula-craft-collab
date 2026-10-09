//! Grant signing and verification: the identity's crypto side of the
//! per-document access model (the types and the access table live in
//! `craft_collab::grant`).
//!
//! A grant is signed by the host's identity key over its domain-separated
//! canonical bytes and verified against the host's carried public key, so a
//! holder can hold the host to exactly what it was given, and a stranger
//! cannot mint a grant. [`KeyGrantVerifier`] is what an `Access` table
//! installs grants through: nothing enters a table unverified.

use std::sync::Arc;

use craft_collab::{Access, GRANT_VERSION, Grant, GrantVerifier, SignedGrant};
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
/// must verify under that key, the key must derive the grant's host id, the
/// version must be current, and the grant must be live. The verifier is the
/// caller holding the host's carried key (from the invite or the document).
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
    if signed.grant.v != GRANT_VERSION {
        return Err(format!("unsupported grant version {}", signed.grant.v));
    }
    if !signed.grant.is_live(now_ms) {
        return Err("the grant is not live".into());
    }
    Ok(signed.grant.clone())
}

/// The host's carried key as a [`GrantVerifier`]: what an [`Access`] table
/// installs grants through, so nothing enters unverified.
pub struct KeyGrantVerifier {
    host_carried_key: Vec<u8>,
    profile: Profile,
}

impl KeyGrantVerifier {
    pub fn new(host_carried_key: Vec<u8>, profile: Profile) -> Self {
        KeyGrantVerifier {
            host_carried_key,
            profile,
        }
    }
}

impl GrantVerifier for KeyGrantVerifier {
    fn verify(&self, signed: &SignedGrant, now_ms: u64) -> Result<Grant, String> {
        verify_grant(signed, &self.host_carried_key, self.profile, now_ms)
    }
}

/// An access table for `doc` whose grants install only when signed by the
/// host that owns `host_carried_key`.
pub fn verified_access(
    doc: &str,
    host: &str,
    host_carried_key: Vec<u8>,
    profile: Profile,
) -> Access {
    Access::new(
        doc,
        host,
        Arc::new(KeyGrantVerifier::new(host_carried_key, profile)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use craft_collab::{Admission, Role};

    fn at(dir: &std::path::Path, slug: &str, name: &str) -> Identity {
        Identity::load_or_create_with(Profile::PqPure, slug, name, None, Some(dir))
            .expect("identity")
    }

    fn grant(host: &Identity, holder: &str, issued: u64, role: Role, nonce: &str) -> Grant {
        Grant {
            v: GRANT_VERSION,
            doc: "demo".into(),
            host: host.node_id().to_string(),
            holder: holder.into(),
            role,
            issued_ms: issued,
            expires_ms: 1_000_000,
            nonce: nonce.into(),
        }
    }

    #[test]
    fn a_grant_verifies_under_the_host_key_only() {
        let dir = tempfile::tempdir().expect("temp dir");
        let host = at(dir.path(), "host", "Host");
        let other = at(dir.path(), "other", "Other");
        let signed =
            sign_grant(&host, &grant(&host, "0011223344", 100, Role::Editor, "n1")).expect("sign");

        assert!(verify_grant(&signed, &host.carried_key(), Profile::PqPure, 500).is_ok());
        assert!(
            verify_grant(&signed, &other.carried_key(), Profile::PqPure, 500).is_err(),
            "another key does not verify it"
        );
        assert!(
            verify_grant(&signed, &host.carried_key(), Profile::PqPure, 2_000_000).is_err(),
            "expiry is enforced"
        );
    }

    #[test]
    fn a_tampered_grant_is_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        let host = at(dir.path(), "host", "Host");
        let signed =
            sign_grant(&host, &grant(&host, "0011223344", 100, Role::Editor, "n1")).expect("sign");

        let mut moved = signed.clone();
        moved.grant.holder = "0099887766".into();
        assert!(
            verify_grant(&moved, &host.carried_key(), Profile::PqPure, 500).is_err(),
            "the holder field is signed"
        );

        let mut loosened = signed.clone();
        loosened.grant.expires_ms = 9_000_000;
        assert!(
            verify_grant(&loosened, &host.carried_key(), Profile::PqPure, 500).is_err(),
            "the expiry is signed"
        );

        let mut rehosted = signed.clone();
        rehosted.grant.host = "0099".into();
        assert!(
            verify_grant(&rehosted, &host.carried_key(), Profile::PqPure, 500).is_err(),
            "the host field is signed"
        );
    }

    #[test]
    fn grants_install_only_through_the_verifier() {
        let dir = tempfile::tempdir().expect("temp dir");
        let host = at(dir.path(), "host", "Host");
        let attacker = at(dir.path(), "attacker", "Attacker");
        let mut access =
            verified_access("demo", host.node_id(), host.carried_key(), Profile::PqPure);

        // A stranger self-asserting Editor with no signature: refused.
        let self_asserted = SignedGrant {
            grant: grant(&host, attacker.node_id(), 200, Role::Editor, "forged"),
            signature: vec![0; 16],
        };
        assert!(
            access.install(&self_asserted, 300).is_err(),
            "an unsigned self-assertion never installs"
        );

        // A grant an attacker signed themselves, claiming the host's id: refused.
        let mut impostor = grant(&host, attacker.node_id(), 200, Role::Editor, "impostor");
        impostor.host = host.node_id().to_string();
        let forged = sign_grant(&attacker, &impostor).expect("attacker signs");
        assert!(
            access.install(&forged, 300).is_err(),
            "the host field must be the signer"
        );

        // The host's own grant: installs, and admits the holder.
        let real = sign_grant(
            &host,
            &grant(&host, attacker.node_id(), 200, Role::Editor, "real"),
        )
        .expect("sign");
        access
            .install(&real, 300)
            .expect("the host's grant installs");
        assert!(
            access
                .admits(
                    attacker.node_id(),
                    &craft_collab::Kind::SnapshotRequest {},
                    300
                )
                .is_admitted()
        );
        assert_eq!(access.len(), 1);

        // A stale renewal (older issued) cannot downgrade the holder.
        let stale = sign_grant(
            &host,
            &grant(&host, attacker.node_id(), 100, Role::Viewer, "stale"),
        )
        .expect("sign");
        assert!(
            access.install(&stale, 300).is_err(),
            "a stale renewal is refused"
        );
        assert_eq!(
            access.admits(
                attacker.node_id(),
                &craft_collab::Kind::TextEdit {
                    para: "1".into(),
                    update: vec![1],
                    props: None
                },
                300
            ),
            Admission::Admitted,
            "still the editor grant"
        );
    }
}
