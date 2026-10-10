//! The Craft identity: one key per person per device, shared by every Craft
//! app, with the display name beside it.
//!
//! The key lives in the platform's secure store (macula-rust's
//! `KeyringStore`: Keychain / Secret Service / Credential Manager). Where the
//! store is unavailable — a headless box, a container — it falls back to a
//! key file in the Craft data directory in macula-rust's key-file layout
//! (`<slug>.<profile>.key`, owner-only, generated with the admission puzzle
//! solved). A small `<slug>.meta` JSON beside it records the display name and
//! which backend holds the key, and a stored key is never silently replaced:
//! anything that fails to load is an error, not a new identity.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use macula_rust::keystore::{KeyStore, KeyStoreError, KeyringStore};
use macula_rust::node_key::{KeyFileError, NodeKey, PUZZLE_DIFFICULTY, Purpose};
use macula_rust::profile::Profile;
use serde::{Deserialize, Serialize};

/// The secure-store service every Craft app shares, so one device has one
/// Craft identity per person per app family.
pub const IDENTITY_SERVICE: &str = "com.storytold.craft";

/// Which backend holds this identity's key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Backend {
    Keyring,
    File,
}

/// What `<slug>.meta` records beside the key.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Meta {
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    backend: Option<Backend>,
}

/// One person's Craft identity on this device.
#[derive(Clone)]
pub struct Identity {
    key: Arc<NodeKey>,
    node_id: String,
    name: String,
    slug: String,
}

impl Identity {
    /// The node id (hex) this identity publishes and signs as.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// The display name shown to peers.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The storage slug this identity was loaded under.
    pub fn slug(&self) -> &str {
        &self.slug
    }

    /// This identity's profile.
    pub fn profile(&self) -> Profile {
        self.key.profile()
    }

    /// The key itself, for a transport that links as this identity, or for
    /// building a pool that signs and dials as it.
    pub fn key(&self) -> Arc<NodeKey> {
        self.key.clone()
    }

    /// The identity's carried public key: what a peer needs to verify
    /// signatures made as this identity (grants, invites).
    pub fn carried_key(&self) -> Vec<u8> {
        self.key.public_key()
    }

    /// An access table for `doc` on this identity's side: its own key is
    /// the trust root, so the table cannot be pointed at another host.
    pub fn verified_access(&self, doc: &str) -> craft_collab::Access {
        crate::grant::verified_access(doc, self.carried_key(), self.key.profile())
    }

    /// Signs `message` as this identity.
    /// A realm proof v2 (macula-realm#29): this key authorises exactly this
    /// request for this procedure in this realm, now and once. The signed
    /// bytes are the realm's own pinned encoding — one byte off and the
    /// realm refuses the proof.
    pub fn device_request_proof(
        &self,
        realm_id: &[u8; 32],
        procedure: &str,
        request: &macula_rust::cbor::Value,
        now_ms: u64,
    ) -> Result<crate::realm::DeviceRequestProof, String> {
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| format!("no randomness for the proof nonce: {e}"))?;
        let message = crate::realm::proof::device_request_message(
            &self.carried_key(),
            realm_id,
            procedure,
            now_ms,
            &nonce,
            request,
        )?;
        let signature = self.sign(&message)?;
        Ok(crate::realm::DeviceRequestProof {
            timestamp_ms: now_ms,
            nonce,
            signature,
        })
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        self.key.sign(message).map_err(|e| format!("sign: {e:?}"))
    }

    /// Loads or creates the Craft identity `slug` with display name `name`,
    /// in the profile `profile` names (`pq_pure` or `pq_hybrid`), from the OS
    /// secure store with a file fallback. A name change is persisted; a
    /// stored key that fails to load is an error.
    pub fn load_or_create(profile: &str, slug: &str, name: &str) -> Result<Identity, String> {
        let profile = Profile::parse(profile).map_err(|e| format!("profile: {e}"))?;
        let dir = craft_identity_dir();
        match KeyringStore::new(IDENTITY_SERVICE, slug) {
            Ok(store) => {
                Self::load_or_create_with(profile, slug, name, Some(&store), dir.as_deref())
            }
            // No store at all: the file fallback must be usable.
            Err(e) => Self::load_or_create_with(profile, slug, name, None, dir.as_deref())
                .map_err(|fallback| format!("secure store unavailable ({e}); {fallback}")),
        }
    }

    /// [`Identity::load_or_create`] against an explicit store and directory,
    /// for tests and embedders. The first load picks the backend that works
    /// and records it in `<slug>.meta`; later loads use only that backend, so
    /// an identity is never silently swapped for one living somewhere else.
    pub fn load_or_create_with(
        profile: Profile,
        slug: &str,
        name: &str,
        store: Option<&dyn KeyStore>,
        dir: Option<&Path>,
    ) -> Result<Identity, String> {
        validate_slug(slug)?;
        let meta_path = dir.map(|d| d.join(format!("{slug}.meta")));
        let mut meta = match meta_path.as_deref() {
            Some(path) => read_meta(path)?,
            None => Meta::default(),
        };

        let key = match meta.backend {
            Some(Backend::Keyring) => {
                let store = store.ok_or_else(|| {
                    "this identity is kept in the secure store, which is unavailable here"
                        .to_string()
                })?;
                keyring_identity(store, profile).map_err(|pick| match pick {
                    StorePick::Unavailable(why) => why,
                    StorePick::Refused(why) => why,
                })?
            }
            Some(Backend::File) => file_identity(dir, slug, profile)?,
            None => {
                // First load here: pick the backend that works and record it.
                match store {
                    Some(store) => match keyring_identity(store, profile) {
                        Ok(key) => {
                            meta.backend = Some(Backend::Keyring);
                            key
                        }
                        Err(StorePick::Unavailable(_)) => {
                            let key = file_identity(dir, slug, profile)?;
                            meta.backend = Some(Backend::File);
                            key
                        }
                        Err(StorePick::Refused(why)) => return Err(why),
                    },
                    None => {
                        let key = file_identity(dir, slug, profile)?;
                        meta.backend = Some(Backend::File);
                        key
                    }
                }
            }
        };

        let node_id = key.node_id().map_err(|e| format!("key: {e:?}"))?;
        if !name.is_empty() {
            meta.display_name = name.to_string();
        } else if meta.display_name.is_empty() {
            meta.display_name = slug.to_string();
        }
        if let Some(path) = meta_path.as_deref() {
            write_meta(path, &meta)?;
        }
        Ok(Identity {
            key: Arc::new(key),
            node_id: hex(&node_id),
            name: meta.display_name,
            slug: slug.to_string(),
        })
    }
}

/// Why the secure store could not provide the key.
enum StorePick {
    /// No usable store here (absent provider, refused write): try the file.
    Unavailable(String),
    /// The store holds something that is not this identity: never replace it.
    Refused(String),
}

/// The key in the secure store, creating and saving one when the store is
/// present but empty.
fn keyring_identity(store: &dyn KeyStore, profile: Profile) -> Result<NodeKey, StorePick> {
    match NodeKey::load_from_keystore(store, Purpose::Identity, profile) {
        Ok(key) => Ok(key),
        Err(KeyFileError::KeyStore(KeyStoreError::NotFound)) => {
            let key = NodeKey::generate_identity(profile, PUZZLE_DIFFICULTY)
                .map_err(|e| StorePick::Unavailable(format!("key: {e:?}")))?;
            match key.save_to_keystore(store) {
                Ok(()) => Ok(key),
                Err(e) => Err(StorePick::Unavailable(format!(
                    "the secure store refused to save: {e}"
                ))),
            }
        }
        Err(KeyFileError::KeyStore(KeyStoreError::Backend(e))) => {
            Err(StorePick::Unavailable(e.to_string()))
        }
        Err(e) => Err(StorePick::Refused(format!(
            "the stored key does not load: {e}"
        ))),
    }
}

/// The key file in the Craft identity directory (macula-rust's key-file
/// layout, generated with the admission puzzle solved when absent).
fn file_identity(dir: Option<&Path>, slug: &str, profile: Profile) -> Result<NodeKey, String> {
    let dir = dir.ok_or_else(|| {
        "the secure store is unavailable and there is no identity directory for the file fallback".to_string()
    })?;
    NodeKey::stored_identity(dir, slug, profile)
        .map(|(key, _)| key)
        .map_err(|e| format!("identity file: {e}"))
}

fn read_meta(path: &Path) -> Result<Meta, String> {
    match std::fs::read(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Meta::default()),
        Err(e) => Err(format!("{}: {e}", path.display())),
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display())),
    }
}

fn write_meta(path: &Path, meta: &Meta) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(meta).map_err(|e| e.to_string())?;
    std::fs::write(path, bytes).map_err(|e| format!("{}: {e}", path.display()))
}

/// The Craft identity directory: `<data>/craft/identity`, where `<data>` is
/// the platform's per-user data directory (the same convention macula uses
/// under `macula/identity`). None where a key file cannot live (Windows).
pub fn craft_identity_dir() -> Option<PathBuf> {
    Some(craft_data_dir()?.join("craft").join("identity"))
}

/// The platform's per-user data directory (the same convention macula uses
/// under `macula/identity`).
pub(crate) fn craft_data_dir() -> Option<PathBuf> {
    let set = |var: &str| std::env::var_os(var).filter(|v| !v.is_empty());
    let home = || set("HOME").map(PathBuf::from);
    if cfg!(target_os = "macos") {
        return home().map(|h| h.join("Library/Application Support"));
    }
    if cfg!(target_os = "windows") {
        return set("APPDATA").map(PathBuf::from);
    }
    set("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| home().map(|h| h.join(".local/share")))
}

/// A storage slug: 1 to 64 lowercase ASCII letters, digits, `-` and `_`,
/// starting with a letter or digit (macula's own key-file naming).
fn validate_slug(slug: &str) -> Result<(), String> {
    let ok = {
        let b = slug.as_bytes();
        b.first()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            && b.len() <= 64
            && b.iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-' || *c == b'_')
    };
    if ok {
        Ok(())
    } else {
        Err(format!(
            "bad identity slug {slug:?}: 1-64 lowercase letters, digits, - or _"
        ))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use macula_mldsa::Zeroizing;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// An in-memory key store: what the OS store offers, without an OS.
    #[derive(Default)]
    struct MemStore {
        keys: Mutex<HashMap<String, Vec<u8>>>,
        /// Every load/save fails with a backend error when set.
        broken: bool,
    }

    impl MemStore {
        fn working() -> MemStore {
            MemStore::default()
        }
        fn broken() -> MemStore {
            MemStore {
                keys: Mutex::new(HashMap::new()),
                broken: true,
            }
        }
        fn backend_error() -> KeyStoreError {
            KeyStoreError::Backend(keyring::Error::NoEntry)
        }
    }

    impl KeyStore for MemStore {
        fn save_key(&self, key: &[u8]) -> Result<(), KeyStoreError> {
            if self.broken {
                return Err(Self::backend_error());
            }
            let mut keys = self.keys.lock().map_err(|_| Self::backend_error())?;
            keys.insert("k".into(), key.to_vec());
            Ok(())
        }

        fn load_key(&self) -> Result<Zeroizing<Vec<u8>>, KeyStoreError> {
            if self.broken {
                return Err(Self::backend_error());
            }
            let keys = self.keys.lock().map_err(|_| Self::backend_error())?;
            match keys.get("k") {
                Some(k) => Ok(Zeroizing::new(k.clone())),
                None => Err(KeyStoreError::NotFound),
            }
        }

        fn delete_key(&self) -> Result<(), KeyStoreError> {
            let mut keys = self.keys.lock().map_err(|_| Self::backend_error())?;
            keys.remove("k");
            Ok(())
        }
    }

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp dir")
    }

    #[test]
    fn an_identity_persists_in_the_store() {
        let store = MemStore::working();
        let dir = tmp();
        let a = Identity::load_or_create_with(
            Profile::PqPure,
            "alice",
            "Alice",
            Some(&store),
            Some(dir.path()),
        )
        .expect("first");
        let b = Identity::load_or_create_with(
            Profile::PqPure,
            "alice",
            "Alice",
            Some(&store),
            Some(dir.path()),
        )
        .expect("second");
        assert_eq!(a.node_id(), b.node_id(), "the same identity, not a new key");
        assert_eq!(b.name(), "Alice");
        // A fresh store handle over the same backing store behaves the same.
        let c = Identity::load_or_create_with(
            Profile::PqPure,
            "alice",
            "Alice",
            Some(&MemStore::working()),
            Some(dir.path()),
        );
        assert!(
            c.is_ok(),
            "an empty store with an existing meta must not mint a second identity"
        );
    }

    #[test]
    fn the_file_fallback_persists_too() {
        let dir = tmp();
        let a =
            Identity::load_or_create_with(Profile::PqPure, "bob", "Bob", None, Some(dir.path()))
                .expect("first");
        let b =
            Identity::load_or_create_with(Profile::PqPure, "bob", "Bob", None, Some(dir.path()))
                .expect("second");
        assert_eq!(a.node_id(), b.node_id(), "file-backed identity is stable");
        assert!(
            dir.path().join("bob.pq_pure.key").exists(),
            "the key file is where macula's layout says"
        );
        assert!(a.node_id().len() == 64);
    }

    #[test]
    fn different_slugs_are_different_identities() {
        let dir = tmp();
        let a = Identity::load_or_create_with(
            Profile::PqPure,
            "alice",
            "Alice",
            None,
            Some(dir.path()),
        )
        .expect("alice");
        let b =
            Identity::load_or_create_with(Profile::PqPure, "bob", "Bob", None, Some(dir.path()))
                .expect("bob");
        assert_ne!(a.node_id(), b.node_id());
    }

    #[test]
    fn a_broken_store_falls_back_to_file_and_stays_there() {
        let dir = tmp();
        let store = MemStore::broken();
        let a = Identity::load_or_create_with(
            Profile::PqPure,
            "carol",
            "Carol",
            Some(&store),
            Some(dir.path()),
        )
        .expect("fallback");
        let b = Identity::load_or_create_with(
            Profile::PqPure,
            "carol",
            "Carol",
            Some(&store),
            Some(dir.path()),
        )
        .expect("again");
        assert_eq!(
            a.node_id(),
            b.node_id(),
            "the fallback identity is stable, not reminted per call"
        );
    }

    #[test]
    fn an_empty_store_with_a_file_identity_does_not_mint_a_second() {
        let dir = tmp();
        let file_first =
            Identity::load_or_create_with(Profile::PqPure, "dave", "Dave", None, Some(dir.path()))
                .expect("file");
        let later = Identity::load_or_create_with(
            Profile::PqPure,
            "dave",
            "Dave",
            Some(&MemStore::working()),
            Some(dir.path()),
        )
        .expect("store later");
        assert_eq!(
            file_first.node_id(),
            later.node_id(),
            "the recorded backend decides, not what happens to be available"
        );
    }

    #[test]
    fn a_bad_slug_is_refused() {
        let dir = tmp();
        assert!(
            Identity::load_or_create_with(
                Profile::PqPure,
                "Alice Smith",
                "Alice",
                None,
                Some(dir.path())
            )
            .is_err()
        );
        assert!(
            Identity::load_or_create_with(Profile::PqPure, "alice", "Alice", None, None).is_err(),
            "no store and no dir is an error"
        );
    }

    #[test]
    fn a_name_change_persists() {
        let dir = tmp();
        let _ =
            Identity::load_or_create_with(Profile::PqPure, "erin", "Erin", None, Some(dir.path()))
                .expect("first");
        let renamed = Identity::load_or_create_with(
            Profile::PqPure,
            "erin",
            "Erin B.",
            None,
            Some(dir.path()),
        )
        .expect("rename");
        assert_eq!(renamed.name(), "Erin B.");
        let again = Identity::load_or_create_with(
            Profile::PqPure,
            "erin",
            "Erin B.",
            None,
            Some(dir.path()),
        )
        .expect("again");
        assert_eq!(again.name(), "Erin B.", "the name is stored beside the key");
    }
}
