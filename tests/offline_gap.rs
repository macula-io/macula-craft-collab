//! What happens to an edit made while a collaborator's *packets* are lost.
//!
//! macula-io/macula-craft-collab#36 measured this over a real black hole and
//! #38 recorded the result: edits made during the gap never reach anyone, and
//! the sender is not told. This test rebuilds that case in process so the
//! cause can be located rather than guessed at.
//!
//! The node keeps its connection the whole time. Its path goes through
//! [`BlackHole`], which drops every datagram for [`GAP`] and then carries them
//! again. QUIC's idle timeout is 300 s, so no link ends, nothing redials and
//! no subscription is replayed: whatever is lost is lost above a connection
//! that was never down. That is deliberately not `Lab::drop_node`, which is
//! the reconnect case and recovers by replay.
//!
//! Run it with the counters printed:
//! `cargo test --test offline_gap -- --nocapture`

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::blackhole::BlackHole;
use common::lab::Lab;
use craft_collab::{BodyParagraph, CollabSession, Inbound, Invite, Role, ShareContext};
use macula_craft_collab::{
    Identity, IdentityIssuer, MeshConfig, MeshTransport, Roster, Share, verified_access_from,
};
use macula_rust::profile::Profile;

const PROFILE: Profile = Profile::PqHybrid;
const PROFILE_NAME: &str = "pq_hybrid";
const REALM_NAME: &str = "io.macula";
const DOC: &str = "demo";
const PARA: &str = "p1";
/// The probe's gap, kept: 30 s is long enough that an edit made in it is not
/// merely late, and far shorter than the 300 s QUIC idle timeout, so the
/// connection cannot close and recover by reconnecting.
const GAP: Duration = Duration::from_secs(30);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn node32(identity: &Identity) -> [u8; 32] {
    let raw: Vec<u8> = (0..identity.node_id().len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(identity.node_id().get(i..i + 2)?, 16).ok())
        .collect();
    raw.try_into().expect("a node id is 32 bytes")
}

fn identity(dir: &std::path::Path, slug: &str, name: &str) -> Identity {
    Identity::load_or_create_with(PROFILE, slug, name, None, Some(dir)).expect("identity")
}

/// The station and realm one test runs against.
struct Realm {
    host: String,
    port: u16,
    node_id: [u8; 32],
    id: [u8; 32],
    key: Vec<u8>,
}

impl Realm {
    fn station(&self) -> SocketAddr {
        format!("{}:{}", self.host, self.port).parse().expect("the station address")
    }

    fn config(&self, share: Share) -> MeshConfig {
        MeshConfig {
            host: self.host.clone(),
            port: self.port,
            station_node_id: self.node_id,
            realm_id: self.id,
            realm_key: self.key.clone(),
            realm_name: REALM_NAME.to_string(),
            share,
            hosting: false,
            membership: None,
            removed: None,
        }
    }
}

/// What a session does with what arrives: the same answers every other share
/// test gives, so a document can converge under test exactly as in the app.
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

fn pump(host: &mut CollabSession, joiner: &mut CollabSession) {
    tick(host);
    tick(joiner);
}

/// Pumps both sides for `for_`, so time passes for the transport too.
async fn pump_for(host: &mut CollabSession, joiner: &mut CollabSession, for_: Duration) {
    let until = std::time::Instant::now() + for_;
    while std::time::Instant::now() < until {
        pump(host, joiner);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// An edit made while the path is down reaches the other side when the path
/// returns, or the person is told it did not leave (#38).
///
/// The counters say where it was lost: `held_to_station` is how many datagrams
/// the node sent into the closed path, so an edit counted there left the node
/// and was lost above the transport; an edit plus no datagram never left it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_edit_made_while_the_path_is_closed_reaches_the_other_side_or_says_it_did_not() {
    let dir = tempfile::tempdir().expect("temp dir");
    let lab = Lab::start(PROFILE);
    let station = lab.station("gap");
    let realm_line = lab.realm(REALM_NAME, "craft");
    let realm = Realm {
        host: station.host.clone(),
        port: station.port,
        node_id: station.node_id,
        id: realm_line.id,
        key: realm_line.key,
    };
    let blackhole = BlackHole::in_front_of(realm.station());

    // Alice hosts the share and dials the station directly.
    let alice = identity(dir.path(), "alice", "Alice");
    let body = [BodyParagraph { para: PARA.into(), text: "Alice writes.".into(), props: None }];
    let prefix = macula_craft_collab::mint_share_prefix(REALM_NAME, alice.node_id()).expect("a share prefix");
    let roster = Roster::new(alice.node_id(), &prefix).expect("the host's admission record");
    let checks = roster.checks();
    let served = MeshTransport::connect(
        &MeshConfig {
            hosting: true,
            share: Share { prefix, ..Share::default() },
            membership: Some(checks.membership),
            removed: Some(checks.removed),
            ..realm.config(Share::default())
        },
        &alice,
    )
    .expect("the host serves its share");
    let group_prefix = served.group_prefix().to_string();
    let mut host = CollabSession::host(DOC, "Alice", Box::new(served), &body);
    host.set_access(alice.verified_access(DOC));
    host.set_issuer(Box::new(IdentityIssuer::new(alice.clone()).with_roster(roster)));
    host.set_auto_approve(true);
    host.set_share_context(ShareContext {
        realm: hex(&realm.id),
        realm_key: hex(&realm.key),
        seed: format!("{}:{}:{}", realm.host, realm.port, hex(&realm.node_id)),
        profile: PROFILE_NAME.to_string(),
        group: group_prefix.clone(),
    });

    // Bob is invited and dials the *relay*, which forwards to the same
    // station, so his path can be closed without his connection ending.
    let bob = identity(dir.path(), "bob", "Bob");
    let line = host.mint_invite_for(None, None, bob.node_id(), "Bob", Role::Editor, 600_000).expect("an invite for Bob");
    let invite = Invite::decode(&line).expect("the invite line");
    let share = Share {
        prefix: invite.group.clone(),
        grant: invite.group_grant.clone().into_bytes(),
        distributor: Some(node32(&alice)),
    };
    let mut behind_the_gap = realm.config(share);
    behind_the_gap.host = blackhole.addr().ip().to_string();
    behind_the_gap.port = blackhole.addr().port();
    let bob_transport = MeshTransport::connect(&behind_the_gap, &bob).expect("the joiner holds the share's key");
    let mut joiner = CollabSession::join_requesting(DOC, "Bob", Box::new(bob_transport), invite.token.clone(), None);
    joiner.set_access(verified_access_from(&invite.doc, &invite.host_key, &invite.profile).expect("the host's key"));

    // The path works before anything is lost: the document reaches Bob.
    for _ in 0..300 {
        pump(&mut host, &mut joiner);
        if joiner.texts().text(PARA) == "Alice writes." {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(joiner.texts().text(PARA), "Alice writes.", "the share works through the relay before the gap");

    // The path closes. Both sides edit while it is closed.
    blackhole.close();
    let alice_offline = host.texts_mut().local_edit(PARA, "Alice writes.", "Alice, offline.").expect("an edit");
    host.send_text(PARA.to_string(), alice_offline, None);
    let bob_offline = joiner.texts_mut().local_edit(PARA, "Alice writes.", "Bob, offline.").expect("an edit");
    joiner.send_text(PARA.to_string(), bob_offline, None);
    pump_for(&mut host, &mut joiner, GAP).await;

    let held_to_station = blackhole.held_to_station();
    let held_from_station = blackhole.held_from_station();
    blackhole.open();
    println!(
        "during the {GAP:?} gap: node->station datagrams dropped {held_to_station}, station->node dropped {held_from_station}"
    );

    // Everything the counters say, and whether the documents converge.
    pump_for(&mut host, &mut joiner, Duration::from_secs(30)).await;
    let alice_text = host.texts().text(PARA);
    let bob_text = joiner.texts().text(PARA);
    println!("after the return: alice reads {alice_text:?}, bob reads {bob_text:?}");
    println!("relayed node->station {}, station->node {}", blackhole.to_station(), blackhole.from_station());
    println!("alice stats {}", host.stats());
    println!("bob stats {}", joiner.stats());

    assert_eq!(
        alice_text, bob_text,
        "the two copies diverge after the path returns: alice {alice_text:?}, bob {bob_text:?}"
    );
    assert!(
        alice_text.contains("offline"),
        "an edit made while the path was closed never reached the other side: {alice_text:?}"
    );
}
