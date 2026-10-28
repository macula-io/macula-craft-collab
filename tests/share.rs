//! A share works end to end over a real station: the host mints a share and
//! serves its key distributor in its own namespace, an invited person pulls
//! the group's key before it knocks, and the document travels sealed between
//! them while a realm member holding no grant reads ciphertext and nothing
//! else (threat model T1).
//!
//! The stations are macula-go's in-process test stations, built to
//! `target/teststation` by `scripts/build-teststation.sh` first, as CI does.

mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use common::lab::Lab;
use craft_collab::{BodyParagraph, CollabSession, GrantIssuer as _, Inbound, Invite, Role, ShareContext};
use macula_craft_collab::{Identity, IdentityIssuer, MeshConfig, MeshTransport, Roster, Share, verified_access_from, verify_invite};
use macula_rust::cbor::Value;
use macula_rust::frame::Payload;
use macula_rust::group::Reason;
use macula_rust::node_key::{NodeKey, PUZZLE_DIFFICULTY};
use macula_rust::pool::{Opts, Pool, Seed};
use macula_rust::profile::Profile;

const PROFILE: Profile = Profile::PqHybrid;
const PROFILE_NAME: &str = "pq_hybrid";
const REALM_NAME: &str = "io.macula";
const DOC: &str = "demo";
const PARA: &str = "p1";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn node32(identity: &Identity) -> [u8; 32] {
    let raw: Vec<u8> =
        (0..identity.node_id().len()).step_by(2).filter_map(|i| u8::from_str_radix(identity.node_id().get(i..i + 2)?, 16).ok()).collect();
    raw.try_into().expect("a node id is 32 bytes")
}

fn identity(dir: &std::path::Path, slug: &str, name: &str) -> Identity {
    Identity::load_or_create_with(PROFILE, slug, name, None, Some(dir)).expect("identity")
}

/// The realm, the station and the share prefix one test runs against.
struct Realm {
    host: String,
    port: u16,
    node_id: [u8; 32],
    id: [u8; 32],
    key: Vec<u8>,
}

impl Realm {
    fn seed(&self) -> String {
        format!("{}:{}:{}", self.host, self.port, hex(&self.node_id))
    }

    fn config(&self, realm_name: &str, share: Share) -> MeshConfig {
        MeshConfig {
            host: self.host.clone(),
            port: self.port,
            station_node_id: self.node_id,
            realm_id: self.id,
            realm_key: self.key.clone(),
            realm_name: realm_name.to_string(),
            share,
            membership: None,
            removed: None,
        }
    }
}

/// A station and its realm, as the share's coordinates.
fn realm(lab: &Lab) -> Realm {
    let station = lab.station("share");
    let realm = lab.realm(REALM_NAME, "craft");
    Realm { host: station.host, port: station.port, node_id: station.node_id, id: realm.id, key: realm.key }
}

/// A host's share served: the transport that holds the share and serves its
/// key distributor, the record that answers the pulls, and the prefix.
struct Served {
    transport: MeshTransport,
    roster: Arc<Roster>,
    group: String,
}

fn serve(realm: &Realm, identity: &Identity) -> Served {
    let roster = Roster::new(identity.node_id()).expect("the host's admission record");
    let checks = roster.checks();
    let cfg = MeshConfig { membership: Some(checks.membership), removed: Some(checks.removed), ..realm.config(REALM_NAME, Share::default()) };
    let transport = MeshTransport::connect(&cfg, identity).expect("the host serves its share");
    let group = transport.group_prefix().to_string();
    Served { transport, roster, group }
}

/// A host sharing `body`: its transport serves the share's key distributor,
/// and its admission record answers the pulls.
struct Host {
    session: CollabSession,
    group: String,
}

fn host(realm: &Realm, identity: Identity, body: &[BodyParagraph]) -> Host {
    let served = serve(realm, &identity);
    let Served { transport, roster, group } = served;
    let mut session = CollabSession::host(DOC, "Alice", Box::new(transport), body);
    session.set_access(identity.verified_access(DOC));
    session.set_issuer(Box::new(IdentityIssuer::new(identity.clone()).with_roster(roster.clone())));
    session.set_auto_approve(true);
    session.set_share_context(ShareContext {
        realm: hex(&realm.id),
        realm_key: hex(&realm.key),
        seed: realm.seed(),
        profile: PROFILE_NAME.to_string(),
        group: group.clone(),
    });
    let _ = roster;
    Host { session, group }
}

/// A group value for a direct pull: `prefix` pulled with `credential` by
/// whoever it was minted for, from the distributor pinned at `distributor`.
fn group(prefix: &str, credential: &str, distributor: [u8; 32]) -> macula_rust::group::Group {
    macula_rust::group::Group { prefix: prefix.to_string(), ucan: credential.as_bytes().to_vec(), distributor: Some(distributor) }
}

/// One node's own pull of a group's key, then it is gone again: a fresh node
/// each time, so an answer is never a keyring's memory of an older one.
async fn pull(
    realm: &Realm,
    identity: &Identity,
    group: &macula_rust::group::Group,
) -> Result<macula_rust::group::Policy, macula_rust::group::GroupError> {
    let mut opts = Opts::new(identity.key());
    opts.realm_trust = HashMap::from([(realm.id, realm.key.clone())]);
    opts.kem_advertise = true;
    let pool =
        Pool::connect(vec![Seed { host: realm.host.clone(), port: realm.port, node_id: realm.node_id }], opts).await.expect("the node connects");
    let joined = pool.join_group(&realm.id, group).await;
    pool.close().await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    joined
}

/// One tick of a session, with the answers an app gives: a snapshot request
/// is answered from the document, and a peer's text update is applied.
fn tick(session: &mut CollabSession) {
    for event in session.tick() {
        match event {
            Inbound::SnapshotWanted => {
                let document = session.texts().full_update();
                session.answer_snapshot(document);
            }
            Inbound::Text { update, .. } => {
                session.texts_mut().apply_doc_update(&update).expect("a peer's update applies");
            }
            Inbound::Snapshot { data, crdt } => {
                session.texts_mut().apply_doc_update(&data).expect("the peer's document applies");
                session.snapshot_loaded(&crdt);
            }
            _ => {}
        }
    }
}

/// One tick of both sides.
fn pump(host: &mut CollabSession, joiner: &mut CollabSession) {
    tick(host);
    tick(joiner);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_share_works_end_to_end_and_a_realm_member_reads_ciphertext_only() {
    let dir = tempfile::tempdir().expect("temp dir");
    let lab = Lab::start(PROFILE);
    let realm = realm(&lab);
    let alice = identity(dir.path(), "alice", "Alice");
    let body = [BodyParagraph { para: PARA.into(), text: "Alice writes.".into(), props: None }];
    let mut host = host(&realm, alice.clone(), &body);

    // The share is what the threat model says it is: this realm's name, this
    // host's own namespace, and a random per-session share id.
    assert_eq!(host.group.split('/').count(), 4, "{} is a four-segment prefix", host.group);
    assert_eq!(host.group.split('/').next(), Some(REALM_NAME));
    assert_eq!(host.group.split('/').nth(1), Some(format!("~{}", alice.node_id()).as_str()));

    // An invite for one named person, which is the only kind a sealed share
    // is handed out with.
    let bob = identity(dir.path(), "bob", "Bob");
    let line = host.session.mint_invite_for(None, None, bob.node_id(), "Bob", Role::Editor, 600_000).expect("an invite for Bob");
    let invite = Invite::decode(&line).expect("the invite line");
    verify_invite(&invite).expect("the host signed it");
    assert_eq!(invite.group, host.group, "the invite carries the share's whole group");
    assert!(!invite.group_grant.is_empty(), "and the credential that pulls its key");
    assert_eq!(invite.invitee.as_deref(), Some(bob.node_id()), "bound to the person it was minted for");

    // A realm member with no grant, watching the share's own topic.
    let eve = Arc::new(NodeKey::generate_identity(PROFILE, PUZZLE_DIFFICULTY).expect("a key"));
    let mut opts = Opts::new(eve);
    opts.realm_trust = HashMap::from([(realm.id, realm.key.clone())]);
    let outsider =
        Pool::connect(vec![Seed { host: realm.host.clone(), port: realm.port, node_id: realm.node_id }], opts).await.expect("a realm member");
    let mut watching = outsider.subscribe(&realm.id, &format!("{}/text_edited_v1", host.group)).await.expect("subscribed to the share's topic");

    // The joiner pulls the group's key from the host's distributor before it
    // knocks, which is only possible because the distributor admits it.
    let bob_transport = {
        let host_id = node32(&alice);
        let share = Share { prefix: invite.group.clone(), grant: invite.group_grant.clone().into_bytes(), distributor: Some(host_id) };
        MeshTransport::connect(&realm.config(REALM_NAME, share), &bob).expect("the joiner holds the share's key")
    };
    let mut joiner = CollabSession::join_requesting(DOC, "Bob", Box::new(bob_transport), invite.token.clone(), None);
    joiner.set_access(verified_access_from(&invite.doc, &invite.host_key, &invite.profile).expect("the host's key"));

    // The document reaches the joiner.
    until("the document reaches the joiner", &mut host.session, &mut joiner, |_, bob_session| bob_session.texts().text(PARA) == "Alice writes.")
        .await;

    // An edit travels sealed, both ways.
    let edit = host.session.texts_mut().local_edit(PARA, "Alice writes.", "Alice writes more.").expect("an edit");
    host.session.send_text(PARA.to_string(), edit, None);
    until("the host's edit reaches the joiner", &mut host.session, &mut joiner, |_, bob_session| {
        bob_session.texts().text(PARA) == "Alice writes more."
    })
    .await;
    assert_eq!(host.session.stats()["unauthorized"], 0, "nothing was refused at the door");

    let edit = joiner.texts_mut().local_edit(PARA, "Alice writes more.", "Bob answers.").expect("an edit");
    joiner.send_text(PARA.to_string(), edit, None);
    until("the joiner's edit reaches the host", &mut host.session, &mut joiner, |alice_session, _| {
        alice_session.texts().text(PARA) == "Bob answers."
    })
    .await;

    // T1: the realm member watching the share's topic read ciphertext and
    // nothing else, and could open none of it.
    let mut heard = 0;
    while let Ok(Some(event)) = tokio::time::timeout(Duration::from_millis(500), watching.recv()).await {
        assert_eq!(event.unopened, Some(Reason::NoGroup), "a node without the group is handed the event unopened");
        assert!(matches!(event.payload, Payload::Clear(Value::Null)), "and with no payload: a ciphertext is never mistaken for one");
        heard += 1;
    }
    assert!(heard > 0, "the member was subscribed to a topic the share used, and heard {heard} events");
}

/// A host and an invited joiner, connected: the joiner holds the share's key
/// and its session presents the invite's token, with the document still to
/// come.
fn paired(realm: &Realm, dir: &std::path::Path) -> (Host, Identity, CollabSession, Invite) {
    let alice = identity(dir, "alice", "Alice");
    let body = [BodyParagraph { para: PARA.into(), text: "Alice writes.".into(), props: None }];
    let host = host(realm, alice.clone(), &body);
    let bob = identity(dir, "bob", "Bob");
    let line = host.session.mint_invite_for(None, None, bob.node_id(), "Bob", Role::Editor, 600_000).expect("an invite for Bob");
    let invite = Invite::decode(&line).expect("the invite line");
    let share = Share { prefix: invite.group.clone(), grant: invite.group_grant.clone().into_bytes(), distributor: Some(node32(&alice)) };
    let transport = MeshTransport::connect(&realm.config(REALM_NAME, share), &bob).expect("the joiner holds the share's key");
    let mut joiner = CollabSession::join_requesting(DOC, "Bob", Box::new(transport), invite.token.clone(), None);
    joiner.set_access(verified_access_from(&invite.doc, &invite.host_key, &invite.profile).expect("the host's key"));
    (host, bob, joiner, invite)
}

/// Pumps both sides until `ok`.
async fn until(what: &str, host: &mut CollabSession, joiner: &mut CollabSession, mut ok: impl FnMut(&CollabSession, &CollabSession) -> bool) {
    for _ in 0..300 {
        pump(host, joiner);
        if ok(host, joiner) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{what} did not happen");
}

/// T3: revocation takes the key away — every epoch of it, past or current —
/// and a grant minted after the revocation is the host's yes again. The
/// revoked holder keeps what it already read: sealing cannot take that back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_holder_is_refused_the_key_until_a_newer_grant() {
    let dir = tempfile::tempdir().expect("temp dir");
    let lab = Lab::start(PROFILE);
    let realm = realm(&lab);
    let alice = identity(dir.path(), "alice", "Alice");
    let bob = identity(dir.path(), "bob", "Bob");
    let served = serve(&realm, &alice);
    let issuer = IdentityIssuer::new(alice.clone()).with_roster(served.roster.clone());
    let now = craft_collab::now_ms();
    let credential = issuer.group_grant(DOC, &served.group, Some(bob.node_id()), 600_000, now).expect("an invite for Bob");
    let share = group(&served.group, &credential, node32(&alice));

    pull(&realm, &bob, &share).await.expect("an invitee pulls the key before it knocks");

    issuer.revoke(DOC, bob.node_id(), now + 1).expect("revoked");
    assert!(served.roster.removed(&served.group, node32(&bob)), "the host's record says removed");
    let refused = pull(&realm, &bob, &share).await.expect_err("a revoked holder is refused every epoch");
    assert_eq!(refused.reason(), Some(Reason::NotAMember), "{refused}");

    issuer.issue(DOC, bob.node_id(), Role::Editor, 600_000, now + 2).expect("re-invited");
    pull(&realm, &bob, &share).await.expect("a grant newer than the revocation is the host's yes again");
}

/// T3, the half sealing cannot do: a revoked holder still holds the epoch
/// key, so its own sealed edit still *opens* for the remaining holders — and
/// is never applied, because the seam, not the seal, is the authority.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_holders_own_edit_is_opened_and_never_applied() {
    let dir = tempfile::tempdir().expect("temp dir");
    let lab = Lab::start(PROFILE);
    let realm = realm(&lab);
    let (mut host, bob, mut joiner, _invite) = paired(&realm, dir.path());
    until("the document reaches Bob", &mut host.session, &mut joiner, |_, bob_session| bob_session.texts().text(PARA) == "Alice writes.").await;

    host.session.revoke(bob.node_id()).expect("revoked");
    // Let the revocation itself travel, so Bob is removed on both sides
    // before it edits.
    for _ in 0..20 {
        pump(&mut host.session, &mut joiner);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Bob seals an edit under the epoch it still holds. It opens for Alice —
    // and the seam refuses to apply it, because Bob is no longer a holder.
    let edit = joiner.texts_mut().local_edit(PARA, "Alice writes.", "Bob was here.").expect("an edit");
    joiner.send_text(PARA.to_string(), edit, None);
    for _ in 0..50 {
        pump(&mut host.session, &mut joiner);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(host.session.texts().text(PARA), "Alice writes.", "the revoked holder's edit was opened and not applied");
    assert!(host.session.stats()["unauthorized"].as_u64().unwrap_or(0) > 0, "and it was counted, not silently dropped");
}

/// T5: the distributor is pinned to the host the invite names. A share whose
/// pin is some other node waits for a distributor that never answers, and
/// publishes nothing meanwhile.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_share_pinned_to_another_node_waits_for_a_distributor_that_never_answers() {
    let dir = tempfile::tempdir().expect("temp dir");
    let lab = Lab::start(PROFILE);
    let realm = realm(&lab);
    let alice = identity(dir.path(), "alice", "Alice");
    let bob = identity(dir.path(), "bob", "Bob");
    let eve = identity(dir.path(), "eve", "Eve");
    let served = serve(&realm, &alice);
    let issuer = IdentityIssuer::new(alice.clone()).with_roster(served.roster.clone());
    let now = craft_collab::now_ms();
    let credential = issuer.group_grant(DOC, &served.group, Some(bob.node_id()), 600_000, now).expect("an invite for Bob");

    let share = Share {
        prefix: served.group.clone(),
        grant: credential.into_bytes(),
        // Eve holds no group key and serves no distributor for this share.
        distributor: Some(node32(&eve)),
    };
    let transport = MeshTransport::connect(&realm.config(REALM_NAME, share), &bob).expect("the transport waits rather than joining nothing");
    assert_eq!(transport.waiting(), Some(Reason::NoDistributor), "the waiting state names what it is waiting for");
}

// T8 — "a holder of share A is refused the key for share B" — is NOT tested
// here, and cannot be yet: both shares of one host have the same org
// (`~<host>`), and the wire names a distributor by `<org>/group_keys_v1`, so
// one host process can serve one distributor. Sharing two documents at once
// therefore needs one pool and one distributor serving several groups, which
// this transport (one share per transport, one pool each) does not do. The
// gap is macula-craft-collab#27; until it lands, a Craft instance shares one
// document, which is what every Craft app's config does today.
