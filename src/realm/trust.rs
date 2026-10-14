//! The realm trust list: which realms' keys this person holds, so a host in
//! one realm can verify a membership attested by another. Trust is a local
//! decision: an invite naming a realm is never enough. A realm enters the
//! list only with its key AND the fingerprint the person checked (the
//! realm's `key_id`, as its `/.well-known/macula-realm.json` publishes it),
//! and a name already trusted under one key is never silently re-keyed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use macula_rust::node_key::key_id_of;
use macula_rust::profile::Profile;
use serde::{Deserialize, Serialize};

use super::{RealmMemberVerifier, realm_id_of};

/// One trusted realm: its name, its key and that key's fingerprint (hex).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedRealm {
    pub name: String,
    pub key: String,
    pub key_id: String,
}

/// A realm's public descriptor, as `/.well-known/macula-realm.json` serves it.
#[derive(Clone, Debug, Deserialize)]
pub struct RealmDescriptor {
    pub realm: String,
    pub realm_id: String,
    pub key_id: String,
    pub profile: String,
    /// Base64 of the realm's carried public key.
    pub public_key: String,
}

impl RealmDescriptor {
    /// Parses a descriptor and checks it is self-consistent: the realm id is
    /// the hash of the name and the key id is the key's own fingerprint.
    /// Consistency is not trust; the person still confirms the fingerprint.
    pub fn parse(json: &str) -> Result<(RealmDescriptor, Vec<u8>), String> {
        use base64::Engine as _;
        let descriptor: RealmDescriptor = serde_json::from_str(json).map_err(|e| format!("not a realm descriptor: {e}"))?;
        if descriptor.profile != "pq_hybrid" {
            return Err(format!("realm {} signs under {}, not pq_hybrid", descriptor.realm, descriptor.profile));
        }
        if !descriptor.realm_id.eq_ignore_ascii_case(&hex::encode(realm_id_of(&descriptor.realm))) {
            return Err(format!("realm {}: its id is not the hash of its name", descriptor.realm));
        }
        let key = base64::engine::general_purpose::STANDARD.decode(descriptor.public_key.trim()).map_err(|e| format!("realm key: {e}"))?;
        if !descriptor.key_id.eq_ignore_ascii_case(&fingerprint(&key)) {
            return Err(format!("realm {}: its key id is not its key's fingerprint", descriptor.realm));
        }
        Ok((descriptor, key))
    }
}

/// A realm key's fingerprint (hex): the key id under the mesh's profile.
pub fn fingerprint(key: &[u8]) -> String {
    hex::encode(key_id_of(key, Profile::PqHybrid))
}

/// The realms this person trusts, by name.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealmTrust {
    realms: BTreeMap<String, TrustedRealm>,
}

impl RealmTrust {
    /// Reads the list; a missing file is an empty list, a damaged one an error
    /// (never quietly an empty list, which would drop every trust decision).
    pub fn load(path: &Path) -> Result<RealmTrust, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(RealmTrust::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    /// Writes the list, owner-readable only.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        let text = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))?;
        super::secure_file(path);
        Ok(())
    }

    /// Trusts `name` under `key`, provided `confirmed_fingerprint` is that
    /// key's fingerprint. Trusting a name again under the same key is a
    /// no-op; under another key it is refused: a rotation is untrust first.
    pub fn trust(&mut self, name: &str, key: &[u8], confirmed_fingerprint: &str) -> Result<&TrustedRealm, String> {
        let name = name.trim();
        if name.is_empty() {
            return Err("a realm needs a name".into());
        }
        let key_id = fingerprint(key);
        if !key_id.eq_ignore_ascii_case(confirmed_fingerprint.trim()) {
            return Err(format!("the fingerprint you checked is not this key's ({key_id}); not trusted"));
        }
        if let Some(existing) = self.realms.get(name)
            && existing.key_id != key_id
        {
            return Err(format!("{name} is already trusted under another key ({}); untrust it first", existing.key_id));
        }
        let entry = self.realms.entry(name.to_string()).or_insert_with(|| TrustedRealm { name: name.to_string(), key: hex::encode(key), key_id });
        Ok(entry)
    }

    /// Trusts the realm a descriptor publishes, only under the name the
    /// person meant (`name`) and the fingerprint they checked. A descriptor
    /// binds its key to its fingerprint; only the person binds the name.
    pub fn trust_descriptor(&mut self, name: &str, descriptor_json: &str, confirmed_fingerprint: &str) -> Result<&TrustedRealm, String> {
        let (descriptor, key) = RealmDescriptor::parse(descriptor_json)?;
        if descriptor.realm != name.trim() {
            return Err(format!("this descriptor is for {}, not {}; not trusted", descriptor.realm, name.trim()));
        }
        self.trust(&descriptor.realm, &key, confirmed_fingerprint)
    }

    /// A trusted realm's entry.
    pub fn entry(&self, name: &str) -> Option<&TrustedRealm> {
        self.realms.get(name.trim())
    }

    /// Stops trusting `name`; whether it was trusted.
    pub fn untrust(&mut self, name: &str) -> bool {
        self.realms.remove(name.trim()).is_some()
    }

    /// The trusted realms, by name.
    pub fn realms(&self) -> impl Iterator<Item = &TrustedRealm> {
        self.realms.values()
    }

    /// A trusted realm's key.
    pub fn key_of(&self, name: &str) -> Option<Vec<u8>> {
        self.realms.get(name.trim()).and_then(|r| hex::decode(&r.key).ok())
    }

    /// The membership verifier for sharing with `name`'s members, when that
    /// realm is trusted.
    pub fn verifier(&self, name: &str, role: craft_collab::Role) -> Result<RealmMemberVerifier, String> {
        let key = self.key_of(name).ok_or_else(|| format!("{name} is not in your trusted realms; add its key and check its fingerprint first"))?;
        Ok(RealmMemberVerifier::new(name.trim(), key, role))
    }
}

/// Where this person's trust list lives: beside the realm credentials.
pub fn trust_path() -> Option<PathBuf> {
    super::realm_dir().map(|dir| dir.join("trusted-realms.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn io_macula() -> (RealmDescriptor, Vec<u8>) {
        RealmDescriptor::parse(include_str!("../../tests/vectors/io.macula.well-known.json")).expect("io.macula's published descriptor")
    }

    #[test]
    fn the_published_descriptor_is_self_consistent_and_its_key_id_is_our_fingerprint() {
        let (descriptor, key) = io_macula();
        assert_eq!(descriptor.realm, "io.macula");
        assert_eq!(fingerprint(&key), "a50fef96e52b4d68ad112ff42b55dc916cd70e5b283280e8cf3cc5e492459cf6");
    }

    #[test]
    fn a_descriptor_whose_key_id_or_realm_id_does_not_match_is_refused() {
        let text = include_str!("../../tests/vectors/io.macula.well-known.json");
        let mut v: serde_json::Value = serde_json::from_str(text).expect("json");
        v["key_id"] = serde_json::Value::String("00".repeat(32));
        assert!(RealmDescriptor::parse(&v.to_string()).is_err(), "a key id that is not the key's");
        let mut v: serde_json::Value = serde_json::from_str(text).expect("json");
        v["realm"] = serde_json::Value::String("net.beam-campus".into());
        assert!(RealmDescriptor::parse(&v.to_string()).is_err(), "a name the realm id is not the hash of");
    }

    #[test]
    fn trust_needs_the_checked_fingerprint_and_never_rekeys_a_name() {
        let (_, key) = io_macula();
        let mut trust = RealmTrust::default();
        assert!(trust.trust("io.macula", &key, &"00".repeat(32)).is_err(), "a fingerprint that is not the key's");
        assert!(trust.key_of("io.macula").is_none());
        let fp = fingerprint(&key);
        trust.trust("io.macula", &key, &fp.to_uppercase()).expect("the checked fingerprint");
        assert_eq!(trust.key_of("io.macula"), Some(key.clone()));
        trust.trust("io.macula", &key, &fp).expect("the same key again is a no-op");

        let other = macula_rust::node_key::NodeKey::generate_identity(Profile::PqHybrid, macula_rust::node_key::PUZZLE_DIFFICULTY).expect("key");
        let other_key = other.public_key();
        assert!(trust.trust("io.macula", &other_key, &fingerprint(&other_key)).is_err(), "a trusted name is never silently re-keyed");
        assert!(trust.untrust("io.macula"));
        trust.trust("io.macula", &other_key, &fingerprint(&other_key)).expect("after untrust, a new key is a fresh decision");
    }

    /// Fable round 1, required 1: the name is bound as well as the key. A
    /// descriptor whose own `realm` is consistent (anyone can hash a name)
    /// but not the realm the person meant to trust is refused.
    #[test]
    fn a_descriptor_is_trusted_only_under_the_name_the_person_meant() {
        let text = include_str!("../../tests/vectors/io.macula.well-known.json");
        let fp = fingerprint(&io_macula().1);
        let mut trust = RealmTrust::default();
        let err = trust.trust_descriptor("net.beam-campus", text, &fp).err().expect("a descriptor for another name");
        assert!(err.contains("io.macula"), "{err}");
        assert!(trust.entry("net.beam-campus").is_none() && trust.entry("io.macula").is_none(), "nothing trusted");
        let entry = trust.trust_descriptor("io.macula", text, &fp).expect("the name meant");
        assert_eq!(entry.key_id, fp);
        assert_eq!(trust.entry(" io.macula ").map(|e| e.key_id.clone()), Some(fp));
    }

    #[test]
    fn the_list_persists_and_a_missing_file_is_empty_but_a_damaged_one_is_an_error() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("trusted-realms.json");
        assert_eq!(RealmTrust::load(&path).expect("missing = empty"), RealmTrust::default());
        let (_, key) = io_macula();
        let mut trust = RealmTrust::default();
        trust.trust("io.macula", &key, &fingerprint(&key)).expect("trust");
        trust.save(&path).expect("save");
        assert_eq!(RealmTrust::load(&path).expect("load"), trust);
        std::fs::write(&path, "{ not json").expect("damage");
        assert!(RealmTrust::load(&path).is_err(), "a damaged list never reads as empty");
    }

    #[test]
    fn a_verifier_exists_only_for_a_trusted_realm() {
        let (_, key) = io_macula();
        let mut trust = RealmTrust::default();
        assert!(trust.verifier("io.macula", craft_collab::Role::Editor).is_err());
        trust.trust("io.macula", &key, &fingerprint(&key)).expect("trust");
        let verifier = trust.verifier("io.macula", craft_collab::Role::Editor).expect("trusted");
        assert_eq!(craft_collab::MembershipVerifier::realm(&verifier), "io.macula");
    }

    /// Juno's walk, steps 3-5, offline: a host attested in realm H shares
    /// with realm E's members. Only a live E membership of the presenting
    /// node admits; H's own memberships, E tokens for someone else and
    /// memberships of a realm the host never trusted do not.
    #[test]
    fn a_host_in_realm_h_admits_a_member_attested_in_realm_e_and_no_one_else() {
        use craft_collab::MembershipVerifier as _;
        use macula_rust::node_key::{NodeKey, PUZZLE_DIFFICULTY};
        use macula_rust::ucan::{Capability, Options, create};

        let gen_key = || NodeKey::generate_identity(Profile::PqHybrid, PUZZLE_DIFFICULTY).expect("key");
        let realm_h = gen_key();
        let realm_e = gen_key();
        let editor = gen_key();
        let someone_else = gen_key();
        let now_s = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock").as_secs() as i64;
        let mint = |realm: &NodeKey, realm_name: &str, audience: &NodeKey| {
            let token = create(
                realm,
                &audience.node_id().expect("node id"),
                &[Capability { with: format!("mri:realm:{realm_name}"), can: super::super::MEMBER_DEVICE_CAN.into() }],
                &Options { exp: now_s + 3_600, ..Options::default() },
            )
            .expect("mint");
            String::from_utf8(token).expect("jwt")
        };
        let editor_hex = hex::encode(editor.node_id().expect("node id"));

        // The host's trust list: its own realm H, and realm E it chose to trust.
        let mut trust = RealmTrust::default();
        trust.trust("test.realm-h", &realm_h.public_key(), &fingerprint(&realm_h.public_key())).expect("trust H");
        trust.trust("test.realm-e", &realm_e.public_key(), &fingerprint(&realm_e.public_key())).expect("trust E");
        let share_with_e = trust.verifier("test.realm-e", craft_collab::Role::Editor).expect("E is trusted");
        let now_ms = (now_s as u64) * 1_000;

        // The editor's E membership admits it, capped at the membership's end.
        let ends = share_with_e.verify_member(&mint(&realm_e, "test.realm-e", &editor), &editor_hex, now_ms).expect("an E member is admitted");
        assert_eq!(ends, ((now_s + 3_600) as u64) * 1_000);
        assert_eq!(share_with_e.role(), craft_collab::Role::Editor);

        // The editor's H membership is not an E membership.
        assert!(share_with_e.verify_member(&mint(&realm_h, "test.realm-h", &editor), &editor_hex, now_ms).is_err(), "H's own members are not E's");
        // H's key claiming E's name: signed by the wrong realm.
        assert!(share_with_e.verify_member(&mint(&realm_h, "test.realm-e", &editor), &editor_hex, now_ms).is_err(), "only E's key speaks for E");
        // An E membership minted for someone else, presented by the editor.
        assert!(
            share_with_e.verify_member(&mint(&realm_e, "test.realm-e", &someone_else), &editor_hex, now_ms).is_err(),
            "the audience is the caller"
        );
        // A realm the host never trusted gets no verifier at all.
        assert!(trust.verifier("test.realm-x", craft_collab::Role::Viewer).is_err());
    }
}
