//! A Craft app taking part in the mesh: the person's identity and realm
//! membership, signing in, and a shared document session from a config file
//! or an invite line. Every Craft app does this the same way, so it lives
//! here once; the app owns the [`CraftMesh`] and installs the
//! [`CollabSession`]s it hands out.
//!
//! A config file (`--collab <config.json>`), host side:
//! ```json
//! {
//!   "station": "<host>:<port>:<station node id hex>",
//!   "realm": "<realm id hex>",
//!   "realm_key": "<realm key hex>",
//!   "doc": "demo",
//!   "name": "Alice",
//!   "identity": "alice",
//!   "join": false,
//!   "auto_approve": true,
//!   "profile": "pq_hybrid"
//! }
//! ```
//! and joiner side, with an invite line from the host instead of the raw
//! coordinates:
//! ```json
//! { "name": "Bob", "identity": "bob", "invite": "{...}" }
//! ```
//! `identity` is the storage slug of this person's persistent Craft key (one
//! key per person per device, shared by every Craft app; secure store, file
//! fallback headless). `join` makes this instance ask a peer for the document
//! first; without it, the instance shares its own document. A host answers
//! join requests with grants (`auto_approve` skips the manual yes; the Share
//! window approves by hand).

use serde::Deserialize;
use serde_json::{Value, json};

use craft_collab::{BodyParagraph, CollabSession, Role, ShareContext, TextStore};

use crate::{Identity, IdentityIssuer, MeshConfig, MeshTransport, RealmCredential, RealmMemberVerifier, RealmTrust, Roster, Share, Tier, hex_bytes};

/// The realm a fresh identity signs in to.
pub const DEFAULT_REALM: &str = "io.macula";

/// The signing profile of the person's default identity.
const DEFAULT_PROFILE: &str = "pq_hybrid";

#[derive(Deserialize)]
struct Config {
    /// `<host>:<port>:<station node id hex>`; also what an invite carries.
    #[serde(default)]
    station: String,
    #[serde(default)]
    realm: String,
    #[serde(default)]
    realm_key: String,
    #[serde(default)]
    doc: String,
    name: String,
    #[serde(default = "default_identity")]
    identity: String,
    #[serde(default)]
    join: bool,
    /// The host admits a valid invite token without asking by hand.
    #[serde(default)]
    auto_approve: bool,
    /// An invite line: join through the invite flow instead of the raw
    /// station/realm fields.
    #[serde(default)]
    invite: Option<String>,
    #[serde(default = "default_profile")]
    profile: String,
    /// The realm name for membership (sign-in).
    #[serde(default = "default_realm_name")]
    realm_name: String,
    /// Share this document with a realm's members: any member presenting a
    /// live membership UCAN is admitted (with `share_role`).
    #[serde(default)]
    share_realm: Option<String>,
    /// The role realm members are admitted with: "viewer" (default) or
    /// "editor".
    #[serde(default)]
    share_role: Option<String>,
    /// Realms to add to this person's trust list before sharing: each a
    /// realm descriptor (`/.well-known/macula-realm.json`, saved to a file)
    /// and the fingerprint the person checked. A realm shared with that is
    /// not the transport's own must be trusted.
    #[serde(default)]
    trust_realms: Vec<TrustRealm>,
}

/// A realm to trust: the descriptor file and the fingerprint the person
/// checked.
#[derive(Deserialize)]
pub struct TrustRealm {
    /// The realm the person means to trust: the descriptor must be for it.
    pub name: String,
    pub descriptor: String,
    pub fingerprint: String,
}

fn default_identity() -> String {
    "default".into()
}

fn default_profile() -> String {
    DEFAULT_PROFILE.into()
}

fn default_realm_name() -> String {
    DEFAULT_REALM.into()
}

/// This person's presence on the mesh in one app: their identity, the realm
/// they sign in to, and a sign-in waiting for confirmation.
pub struct CraftMesh {
    identity: Identity,
    realm_name: String,
    base: String,
    pending: Option<String>,
}

impl CraftMesh {
    /// `identity` signing in to `realm_name` through that realm's portal.
    pub fn new(identity: Identity, realm_name: &str) -> CraftMesh {
        let base = crate::realm::session::realm_base_url(realm_name);
        CraftMesh::with_portal(identity, realm_name, &base)
    }

    /// The same with an explicit portal base URL (tests, a local realm).
    pub fn with_portal(identity: Identity, realm_name: &str, base: &str) -> CraftMesh {
        CraftMesh { identity, realm_name: realm_name.to_string(), base: base.to_string(), pending: None }
    }

    /// The person's default identity on this device, loaded with an empty
    /// name (a stored display name is never rewritten; a fresh identity is
    /// named in the Sign in window, never guessed), signing in to
    /// [`DEFAULT_REALM`]. An app loads it at startup so its realm row works
    /// before any document is shared.
    pub fn default_identity() -> Result<CraftMesh, String> {
        crate::identity::craft_identity_dir().ok_or_else(|| "no per-user data directory for the identity".to_string())?;
        let identity = Identity::load_or_create(DEFAULT_PROFILE, "default", "")?;
        Ok(CraftMesh::new(identity, DEFAULT_REALM))
    }

    /// [`CraftMesh::default_identity`] at an explicit directory (tests and
    /// embedders), file backend only.
    pub fn default_identity_at(dir: &std::path::Path) -> Result<CraftMesh, String> {
        let identity = Identity::load_or_create_at(DEFAULT_PROFILE, "default", "", dir)?;
        Ok(CraftMesh::new(identity, DEFAULT_REALM))
    }

    /// This person's identity.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// The display name, as the Sign in window shows it: `default` is true
    /// while the name is still the storage slug (nobody named it yet).
    pub fn identity_name(&self) -> Value {
        json!({"name": self.identity.name(), "slug": self.identity.slug(), "default": self.identity.name_is_slug()})
    }

    /// Sets the person's display name (persisted beside the key; later
    /// startups keep it).
    pub fn set_identity_name(&mut self, name: &str) -> Result<Value, String> {
        self.identity.set_display_name(name)?;
        Ok(json!({"name": self.identity.name(), "default": self.identity.name_is_slug()}))
    }

    /// The stored realm membership, as the share windows read it.
    pub fn realm_status(&self) -> Value {
        let cred = crate::realm::load_credential(self.identity.node_id(), &self.realm_name);
        realm_status_json(&self.realm_name, cred.as_ref())
    }

    /// Starts the realm's citizen join session: the link the person opens
    /// (or scans); [`CraftMesh::sign_in_check`] polls it.
    pub fn sign_in(&mut self) -> Result<Value, String> {
        let created = crate::realm::session::create_session(&self.realm_name, &self.base, &self.identity, craft_collab::now_ms())?;
        self.pending = Some(created.session_id.clone());
        Ok(json!({"portal": self.base, "joinUrl": created.join_url, "sessionId": created.session_id, "expiresAt": created.expires_at}))
    }

    /// Polls the waiting sign-in. On a confirmation the credential is stored
    /// beside the identity keys and the answer is the fresh membership status
    /// (it carries `signedIn`); otherwise it is the sign-in's own `status`:
    /// pending, expired or none.
    pub fn sign_in_check(&mut self) -> Result<Value, String> {
        let Some(session_id) = self.pending.clone() else { return Ok(json!({"status": "none"})) };
        match crate::realm::session::poll_session(&self.base, &session_id)? {
            crate::realm::SessionStatus::Pending { expires_at } => Ok(json!({"status": "pending", "expiresAt": expires_at})),
            crate::realm::SessionStatus::Expired => {
                self.pending = None;
                Ok(json!({"status": "expired"}))
            }
            crate::realm::SessionStatus::Error(e) => Err(e),
            crate::realm::SessionStatus::Confirmed(confirmed) => {
                let cred =
                    crate::realm::session::credential_from_confirmed(&self.identity, &self.realm_name, &self.base, confirmed, craft_collab::now_ms());
                crate::realm::store_credential(&cred)?;
                self.pending = None;
                Ok(realm_status_json(&self.realm_name, Some(&cred)))
            }
        }
    }

    /// Reads the config at `path` and shares or joins its document. `body`
    /// is the app's document body when this instance shares it (empty for
    /// an app without flowing text). The mesh presence the config names
    /// comes back with the session.
    pub fn attach(path: &str, body: &[BodyParagraph]) -> Result<(CraftMesh, CollabSession), String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        let cfg: Config = serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))?;
        let identity = Identity::load_or_create(&cfg.profile, &cfg.identity, &cfg.name)?;
        let mesh = CraftMesh::new(identity.clone(), &cfg.realm_name);
        if let Some(line) = &cfg.invite {
            let session = join_line(&identity, &cfg.name, line)?;
            return Ok((mesh, session));
        }
        if cfg.station.is_empty() || cfg.realm.is_empty() {
            return Err(format!("{path}: station and realm are required without an invite"));
        }
        // A raw-coordinates instance mints the share's group, which is what
        // makes it the share's key distributor. `join` asks the peers for the
        // document, but it cannot name the group: a share id is random and
        // per session, so a session that ends takes its prefix with it. An
        // instance that should rejoin does so through a fresh invite line,
        // never by guessing a prefix and sharing a private room of one.
        if cfg.join {
            return Err(format!(
                "{path}: a share's group is minted per session, so an instance that joins needs an invite line, not raw station and realm coordinates"
            ));
        }
        // The share's group, minted here because the admission record is
        // about exactly this prefix and no other (threat model T8): a holder
        // of one share is nobody in another, even another of this host's.
        let prefix = crate::mint_share_prefix(&cfg.realm_name, identity.node_id())?;
        let roster = Roster::new(identity.node_id(), &prefix).map_err(|e| format!("{path}: the share's admission record: {e}"))?;
        let checks = roster.checks();
        let share = Share { prefix: prefix.clone(), ..Share::default() };
        let mut config = mesh_config(&cfg.station, &cfg.realm, &cfg.realm_name, &cfg.realm_key, share)?;
        config.hosting = true;
        config.membership = Some(checks.membership);
        config.removed = Some(checks.removed);
        let transport = MeshTransport::connect(&config, &identity)?;
        // The share this session carries: the session needs it to put in
        // every invite it mints from here on.
        let share_group = transport.group_prefix().to_string();
        // A raw-coordinates config is the document owner's instance: it holds
        // the access table, mints grants and can invite.
        let mut session = CollabSession::host(&cfg.doc, &cfg.name, Box::new(transport), body);
        session.set_access(identity.verified_access(&cfg.doc));
        session.set_issuer(Box::new(IdentityIssuer::new(identity.clone()).with_roster(roster)));
        session.set_auto_approve(cfg.auto_approve);
        let trust_path = crate::realm::trust::trust_path();
        if !cfg.trust_realms.is_empty() {
            let trust_path = trust_path.as_deref().ok_or("no config directory for the realm trust list")?;
            trust_realms(trust_path, &cfg.trust_realms).map_err(|e| format!("{path}: {e}"))?;
        }
        if let Some(realm) = cfg.share_realm.as_deref() {
            let role = match cfg.share_role.as_deref() {
                Some("editor") => Role::Editor,
                None | Some("viewer") => Role::Viewer,
                Some(other) => return Err(format!("{path}: unknown share_role `{other}` (viewer or editor)")),
            };
            let verifier = share_verifier(realm, role, &cfg.realm, &cfg.realm_key, trust_path.as_deref()).map_err(|e| format!("{path}: {e}"))?;
            session.set_member_verifier(Box::new(verifier));
        }
        session.set_share_context(ShareContext {
            realm: cfg.realm,
            realm_key: cfg.realm_key,
            seed: cfg.station,
            profile: cfg.profile,
            group: share_group,
        });
        if let Some(store) = person_file(&format!("{}.{}.grants.json", safe_slug(&cfg.identity), safe_slug(&cfg.doc))) {
            session.set_grants_store(Box::new(store));
        }
        if let Some(store) = person_file(&format!("{}.contacts.json", safe_slug(&cfg.identity))) {
            session.set_contacts_store(Box::new(store));
        }
        Ok((mesh, session))
    }

    /// Joins through an invite line (the Share window, or a config): the
    /// invite names the document, the host and its key, the realm and a seed
    /// station, plus the host-signed token this instance presents. The
    /// person's default identity joins as `name`.
    pub fn join_invite(invite_line: &str, name: &str) -> Result<(CraftMesh, CollabSession), String> {
        let identity = Identity::load_or_create(DEFAULT_PROFILE, "default", name)?;
        // The invite carries the realm id, not its name; io.macula is today's
        // realm, and the realm row must work after pasting one too.
        let mesh = CraftMesh::new(identity.clone(), DEFAULT_REALM);
        let session = join_line(&identity, name, invite_line)?;
        Ok((mesh, session))
    }
}

fn realm_status_json(realm_name: &str, cred: Option<&RealmCredential>) -> Value {
    match cred {
        None => json!({"signedIn": false, "realm": realm_name}),
        Some(cred) => json!({
            "signedIn": true,
            "realm": cred.realm,
            "tier": match cred.tier {
                Tier::Device => "device",
                Tier::Citizen => "citizen",
            },
            "handle": cred.handle(),
            "orgIdentity": cred.org_identity,
            "joinedAtMs": cred.joined_at_ms,
            "ucanExpiresMs": cred.ucan_expires_ms(),
        }),
    }
}

/// Adds each descriptor to the trust list at `path`, refusing the lot on the
/// first one that does not parse or whose fingerprint was not the one checked.
pub fn trust_realms(path: &std::path::Path, realms: &[TrustRealm]) -> Result<(), String> {
    let mut trust = RealmTrust::load(path)?;
    for entry in realms {
        let text = std::fs::read_to_string(&entry.descriptor).map_err(|e| format!("{}: {e}", entry.descriptor))?;
        trust.trust_descriptor(&entry.name, &text, &entry.fingerprint)?;
    }
    trust.save(path)
}

/// The verifier for sharing with `realm`'s members. The transport's own
/// realm is already pinned by the config (its key is what advertisements
/// verify under); any other realm must be in this person's trust list.
pub fn share_verifier(
    realm: &str,
    role: Role,
    transport_realm_id: &str,
    transport_realm_key: &str,
    trust_path: Option<&std::path::Path>,
) -> Result<RealmMemberVerifier, String> {
    let realm = realm.trim();
    let trust = match trust_path {
        Some(path) => RealmTrust::load(path)?,
        None => RealmTrust::default(),
    };
    let is_transport_realm = hex_bytes(transport_realm_id).is_ok_and(|id| id == crate::realm::realm_id_of(realm));
    if is_transport_realm && !transport_realm_key.is_empty() {
        let key = hex_bytes(transport_realm_key)?;
        config_key_agrees_with_trust(&trust, realm, &key)?;
        return Ok(RealmMemberVerifier::new(realm, key, role));
    }
    trust.verifier(realm, role)
}

/// A checked trust entry for the same realm outranks an unchecked config key:
/// they must agree, or nothing is shared.
fn config_key_agrees_with_trust(trust: &RealmTrust, realm: &str, key: &[u8]) -> Result<(), String> {
    let Some(entry) = trust.entry(realm) else {
        return Ok(());
    };
    let pinned = crate::realm::trust::fingerprint(key);
    if pinned == entry.key_id {
        return Ok(());
    }
    Err(format!("{realm}: the config's key ({pinned}) is not the one you trusted ({}); fix one of them", entry.key_id))
}

fn join_line(identity: &Identity, name: &str, line: &str) -> Result<CollabSession, String> {
    let invite = craft_collab::Invite::decode(line.trim())?;
    // The joiner verifies who invited it before connecting anywhere.
    crate::verify_invite(&invite)?;
    // A realm invite carries no token: present this device's membership of
    // the realm the invite names (possibly not the host's own), when it
    // holds one.
    let membership = match (&invite.member_role, invite.member_realm.as_deref()) {
        (Some(_), Some(member_realm)) => crate::realm::load_credential(identity.node_id(), member_realm).and_then(|cred| cred.ucan),
        _ => None,
    };
    if !invite.is_live(craft_collab::now_ms()) {
        return Err("this invite has expired".into());
    }
    // A shared document travels sealed, so the invite must carry the share's
    // group and the credential that pulls its key. An invite minted by a
    // session that does not seal names neither, and joining it would put this
    // person's edits in the open: refused, visibly, rather than joined.
    if invite.group.is_empty() || invite.group_grant.is_empty() {
        return Err("this invite is from a session that does not seal; ask the host for a fresh line".into());
    }
    // The host's node is the share's distributor, and the invite pins it: a
    // node that advertises itself as the distributor instead is refused.
    let realm_name = invite.group.split('/').next().unwrap_or_default().to_string();
    let share = Share {
        prefix: invite.group.clone(),
        grant: invite.group_grant.clone().into_bytes(),
        distributor: Some(hex32(&invite.host).map_err(|e| format!("the host's node id: {e}"))?),
    };
    let transport = MeshTransport::connect(&mesh_config(&invite.seed, &invite.realm, &realm_name, &invite.realm_key, share)?, identity)?;
    let mut session = CollabSession::join_requesting(&invite.doc, name, Box::new(transport), invite.token.clone(), membership);
    session.set_access(crate::verified_access_from(&invite.doc, &invite.host_key, &invite.profile)?);
    // The host is the first person this joiner meets: remember them (the
    // invite carries their name) in this person's own contact list.
    if let Some(store) = person_file(&format!("{}.contacts.json", safe_slug(identity.slug()))) {
        session.set_contacts_store(Box::new(store));
    }
    session.note_contact(&invite.host, &invite.host_name, invite.host_realm.as_deref());
    Ok(session)
}

fn mesh_config(seed: &str, realm: &str, realm_name: &str, realm_key: &str, share: Share) -> Result<MeshConfig, String> {
    let mut parts = seed.rsplitn(3, ':');
    let (Some(node_hex), Some(port), Some(host)) = (parts.next(), parts.next(), parts.next()) else {
        return Err("a station seed must be host:port:node_hex".into());
    };
    Ok(MeshConfig {
        host: host.to_string(),
        port: port.parse::<u16>().map_err(|e| format!("station port: {e}"))?,
        station_node_id: hex32(node_hex).map_err(|e| format!("station node id: {e}"))?,
        realm_id: hex32(realm).map_err(|e| format!("realm: {e}"))?,
        realm_key: hex_bytes(realm_key).map_err(|e| format!("realm key: {e}"))?,
        realm_name: realm_name.to_string(),
        share,
        hosting: false,
        // A joiner serves nothing: the host's checks are set by the host path
        // that mints the share's group.
        membership: None,
        removed: None,
    })
}

/// One of this person's collaboration files in `craft/collab/` under the
/// config directory (grants per document, contacts per person), shared by
/// every Craft app. `None` when no config directory is known.
fn person_file(name: &str) -> Option<PersonFile> {
    let base = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var("HOME").ok().map(|h| std::path::PathBuf::from(h).join(".config")))?;
    let dir = base.join("craft").join("collab");
    std::fs::create_dir_all(&dir).ok()?;
    Some(PersonFile(dir.join(name)))
}

/// A collaboration file in the person's config directory.
struct PersonFile(std::path::PathBuf);

impl TextStore for PersonFile {
    fn read(&self) -> Option<String> {
        std::fs::read_to_string(&self.0).ok()
    }

    /// A failed write never takes the collaboration down.
    fn write(&self, text: &str) {
        let _ = std::fs::write(&self.0, text);
    }
}

/// A filename-safe slug for an identity or document id.
fn safe_slug(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect()
}

fn hex32(s: &str) -> Result<[u8; 32], String> {
    let v = hex_bytes(s)?;
    let n = v.len();
    v.try_into().map_err(|_| format!("expected 32 bytes, got {n}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use craft_collab::MembershipVerifier as _;

    const IO_MACULA: &str = include_str!("../tests/vectors/io.macula.well-known.json");
    const IO_MACULA_ID: &str = "abb81b5a614b63551b400b810648c0c8a78efad845442630c94b46cc95d2fcd1";
    const IO_MACULA_FP: &str = "a50fef96e52b4d68ad112ff42b55dc916cd70e5b283280e8cf3cc5e492459cf6";

    fn trusted(name: &str, descriptor: &std::path::Path, fingerprint: &str) -> [TrustRealm; 1] {
        [TrustRealm { name: name.into(), descriptor: descriptor.display().to_string(), fingerprint: fingerprint.into() }]
    }

    /// Sharing with a realm that is not the transport's needs it in the trust
    /// list, entered with the checked fingerprint; the transport's own realm
    /// is already pinned by config.
    #[test]
    fn sharing_with_another_realm_needs_it_trusted_under_the_checked_fingerprint() {
        let dir = tempfile::tempdir().expect("dir");
        let trust = dir.path().join("trusted-realms.json");
        let descriptor = dir.path().join("io.macula.json");
        std::fs::write(&descriptor, IO_MACULA).expect("descriptor");
        let other_transport = "cc".repeat(32);

        let Err(err) = share_verifier("io.macula", Role::Editor, &other_transport, "ee", Some(&trust)) else { panic!("refused") };
        assert!(err.contains("trusted realms"), "{err}");

        assert!(trust_realms(&trust, &trusted("io.macula", &descriptor, &"00".repeat(32))).is_err(), "a fingerprint that is not the key's");
        assert!(share_verifier("io.macula", Role::Editor, &other_transport, "ee", Some(&trust)).is_err());

        assert!(
            trust_realms(&trust, &trusted("net.beam-campus", &descriptor, IO_MACULA_FP)).is_err(),
            "the person names the realm, not the descriptor"
        );
        assert!(share_verifier("net.beam-campus", Role::Editor, &other_transport, "ee", Some(&trust)).is_err());

        trust_realms(&trust, &trusted("io.macula", &descriptor, IO_MACULA_FP)).expect("trusted");
        let verifier = share_verifier("io.macula", Role::Editor, &other_transport, "ee", Some(&trust)).expect("now trusted");
        assert_eq!(verifier.realm(), "io.macula");
        assert_eq!(verifier.role(), Role::Editor);
    }

    /// An unchecked config key never overrides a checked trust entry for the
    /// same realm.
    #[test]
    fn a_config_key_that_disagrees_with_the_trusted_one_shares_nothing() {
        let dir = tempfile::tempdir().expect("dir");
        let trust = dir.path().join("trusted-realms.json");
        let descriptor = dir.path().join("io.macula.json");
        std::fs::write(&descriptor, IO_MACULA).expect("descriptor");
        trust_realms(&trust, &trusted("io.macula", &descriptor, IO_MACULA_FP)).expect("trusted");
        let Err(err) = share_verifier("io.macula", Role::Viewer, IO_MACULA_ID, "ee", Some(&trust)) else { panic!("a disagreeing key") };
        assert!(err.contains(IO_MACULA_FP), "{err}");
        let (_, key) = crate::RealmDescriptor::parse(IO_MACULA).expect("vector");
        let key_hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        share_verifier("io.macula", Role::Viewer, IO_MACULA_ID, &key_hex, Some(&trust)).expect("agreeing keys share");
    }

    #[test]
    fn the_transport_realm_is_shared_with_under_its_pinned_key() {
        let dir = tempfile::tempdir().expect("dir");
        let verifier = share_verifier("io.macula", Role::Viewer, IO_MACULA_ID, "ee", Some(&dir.path().join("none.json"))).expect("pinned by config");
        assert_eq!(verifier.realm(), "io.macula");
    }

    /// A plain run (no config) pressing Share then Sign in: the default
    /// identity reaches the membership, and sign-in fails only on the portal,
    /// never on a missing identity.
    #[test]
    fn the_default_identity_reaches_the_realm_without_an_identity_error() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mesh = CraftMesh::default_identity_at(dir.path()).expect("the default identity loads");
        assert_eq!(mesh.realm_status()["signedIn"], false, "no membership yet, and no error");
        let identity = Identity::load_or_create_at("pq_hybrid", "default", "", dir.path()).expect("identity");
        let mut unreachable = CraftMesh::with_portal(identity, "io.macula", "http://127.0.0.1:9");
        let err = unreachable.sign_in().expect_err("an unreachable portal fails the call");
        assert!(!err.contains("identity"), "not an identity error: {err}");
        assert_eq!(unreachable.sign_in_check().expect("check")["status"], "none", "a failed start leaves nothing waiting");
    }

    /// The Sign in window names a fresh identity; startup never guesses or
    /// clobbers, and the chosen name survives later startups.
    #[test]
    fn a_stored_name_is_never_clobbered_by_the_default_identity() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut mesh = CraftMesh::default_identity_at(dir.path()).expect("loads");
        assert_eq!(mesh.identity_name()["default"], true, "a fresh identity is unnamed");
        mesh.set_identity_name("First Name").expect("named");
        assert_eq!(mesh.identity_name()["name"], "First Name");
        assert!(mesh.set_identity_name("   ").is_err(), "an empty name is refused");
        let again = CraftMesh::default_identity_at(dir.path()).expect("a later startup");
        assert_eq!(again.identity_name()["name"], "First Name", "the stored name survives");
        assert_eq!(again.identity_name()["default"], false);
    }

    #[test]
    fn hex_and_seeds_refuse_junk_without_panicking() {
        assert!(hex_bytes("abc").is_err());
        assert!(hex_bytes("zz").is_err());
        assert!(hex_bytes("éé").is_err());
        assert!(mesh_config("no-colons", &"aa".repeat(32), "io.macula", "", Share::default()).is_err());
        assert!(mesh_config("h:99999:aa", &"aa".repeat(32), "io.macula", "", Share::default()).is_err());
        assert_eq!(safe_slug("a/b c"), "a_b_c");
    }
}
