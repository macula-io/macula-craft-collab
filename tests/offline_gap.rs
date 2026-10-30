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
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::blackhole::BlackHole;
use common::lab::Lab;
use craft_collab::{
    BodyParagraph, CollabSession, Inbound, Invite, Kind, Message, Role, ShareContext, Transport,
};
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

/// How long a run watches the path after it reopens. QUIC backs its PTO off
/// while nothing is acknowledged, so an edit queued in the gap can be resent
/// well after the path is back: a short window cannot tell "lost" from "late".
/// This stays under QUIC's 300 s idle timeout, so the link cannot end and
/// recover by redialling.
const AFTER: Duration = Duration::from_secs(150);

/// What a [`Watched`] transport saw cross it, in order, as `s:seq` when this
/// side sent and `r:<author>:<seq>` when one arrived.
type Log = Arc<Mutex<Vec<String>>>;

/// A transport that records every message that arrives, *before* the session
/// orders it. That is the one place that tells "never arrived" from "arrived
/// and was held" ([`OrderBuffer`](craft_collab::OrderBuffer)): the documents
/// alone cannot, because both look like nothing happening.
struct Watched {
    inner: MeshTransport,
    log: Log,
}

impl Transport for Watched {
    fn author(&self) -> String {
        self.inner.author()
    }

    fn send(&mut self, msg: Message) -> Result<(), String> {
        note(&self.log, format!("s:{}", msg.seq));
        self.inner.send(msg)
    }

    fn poll(&mut self) -> Vec<Message> {
        let arrived = self.inner.poll();
        for msg in &arrived {
            note(&self.log, format!("r:{}:{} ({})", short(&msg.author), msg.seq, kind_name(&msg.kind)));
        }
        arrived
    }

    fn membership(&self) -> Option<String> {
        self.inner.membership()
    }
}

fn note(log: &Log, entry: String) {
    if let Ok(mut entries) = log.lock() {
        entries.push(entry);
    }
}

/// The entries a log holds, for printing and for the assertions below.
fn entries(log: &Log) -> Vec<String> {
    log.lock().map(|entries| entries.clone()).unwrap_or_default()
}

/// The sequence number of the last message this side sent.
fn last_sent(log: &Log) -> Option<u64> {
    entries(log).iter().rev().find_map(|entry| entry.strip_prefix("s:")).and_then(|seq| seq.parse().ok())
}

/// Whether `seq` from `author` reached this side's transport, whatever the
/// session then did with it.
fn arrived(log: &Log, author: &str, seq: u64) -> bool {
    let wanted = format!("r:{author}:{seq}");
    entries(log).iter().any(|entry| entry.split_whitespace().next() == Some(wanted.as_str()))
}

/// The first author whose messages arrived on this side.
fn first_author(log: &Log) -> String {
    entries(log)
        .iter()
        .filter_map(|entry| entry.strip_prefix("r:"))
        .filter_map(|rest| rest.split(':').next())
        .next()
        .unwrap_or_default()
        .to_string()
}

/// The first eight hex characters of an author id: enough to tell two apart.
fn short(author: &str) -> &str {
    author.get(..8).unwrap_or(author)
}

fn kind_name(kind: &Kind) -> &'static str {
    match kind {
        Kind::TextEdit { .. } => "text",
        Kind::CursorMoved { .. } => "cursor",
        Kind::Command { .. } => "command",
        Kind::SnapshotRequest {} => "snapshot-wanted",
        Kind::Snapshot { .. } => "snapshot",
        Kind::JoinRequest { .. } => "join",
        Kind::GrantIssued { .. } => "grant",
        Kind::Revoked { .. } => "revoked",
    }
}

/// Everything one run needs, set up the same way for every case below.
struct Gap {
    lab: Lab,
    host: CollabSession,
    joiner: CollabSession,
    blackhole: BlackHole,
    alice_log: Log,
    bob_log: Log,
}

/// Alice hosts and dials the station; Bob is invited and dials a relay in
/// front of it, so his path can be closed without his connection ending. The
/// document is already in sync on return.
async fn open_gap(dir: &std::path::Path) -> Gap {
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
    let alice = identity(dir, "alice", "Alice");
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
    let alice_log: Log = Arc::new(Mutex::new(Vec::new()));
    let watched = Watched { inner: served, log: Arc::clone(&alice_log) };
    let mut host = CollabSession::host(DOC, "Alice", Box::new(watched), &body);
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
    let bob = identity(dir, "bob", "Bob");
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
    let bob_log: Log = Arc::new(Mutex::new(Vec::new()));
    let watched = Watched { inner: bob_transport, log: Arc::clone(&bob_log) };
    let mut joiner = CollabSession::join_requesting(DOC, "Bob", Box::new(watched), invite.token.clone(), None);
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

    Gap { lab, host, joiner, blackhole, alice_log, bob_log }
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
    let mut gap = open_gap(dir.path()).await;
    let Gap { host, joiner, blackhole, lab: _lab, alice_log: _, bob_log: _ } = &mut gap;

    // The path closes. Both sides edit while it is closed.
    blackhole.close();
    let alice_offline = host.texts_mut().local_edit(PARA, "Alice writes.", "Alice, offline.").expect("an edit");
    host.send_text(PARA.to_string(), alice_offline, None);
    let bob_offline = joiner.texts_mut().local_edit(PARA, "Alice writes.", "Bob, offline.").expect("an edit");
    joiner.send_text(PARA.to_string(), bob_offline, None);
    pump_for(host, joiner, GAP).await;

    let held_to_station = blackhole.held_to_station();
    let held_from_station = blackhole.held_from_station();
    blackhole.open();
    println!(
        "during the {GAP:?} gap: node->station datagrams dropped {held_to_station}, station->node dropped {held_from_station}"
    );

    // Everything the counters say, and whether the documents converge.
    pump_for(host, joiner, Duration::from_secs(30)).await;
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

/// "Lost" and "late" are different findings, and only a long window tells
/// them apart: QUIC backs its PTO off while nothing is acknowledged, so a
/// message queued in the gap can still be resent well after the path is back.
///
/// The edit made once the path is back separates the other two cases: if it
/// arrives while the offline one never does, the loss is that one message; if
/// nothing more arrives from that author, the receiver's order buffer has
/// stalled that stream for the rest of the session (rgfaber/craft-libs#2).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn whether_the_offline_edit_was_lost_or_only_late_needs_a_long_window() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut gap = open_gap(dir.path()).await;
    let Gap { host, joiner, blackhole, lab: _lab, alice_log: _, bob_log: _ } = &mut gap;

    blackhole.close();
    let alice_offline = host.texts_mut().local_edit(PARA, "Alice writes.", "Alice, offline.").expect("an edit");
    host.send_text(PARA.to_string(), alice_offline, None);
    let bob_offline = joiner.texts_mut().local_edit(PARA, "Alice writes.", "Bob, offline.").expect("an edit");
    joiner.send_text(PARA.to_string(), bob_offline, None);
    pump_for(host, joiner, GAP).await;

    let sent_into_the_gap = blackhole.held_to_station();
    blackhole.open();
    println!("the path was closed for {GAP:?} and the node sent {sent_into_the_gap} datagrams into it");

    let reopened = std::time::Instant::now();
    while reopened.elapsed() < AFTER {
        pump_for(host, joiner, Duration::from_secs(5)).await;
        let alice = host.texts().text(PARA);
        let bob = joiner.texts().text(PARA);
        println!(
            "+{:?}: alice {alice:?}, bob {bob:?}; relayed {} up, {} down",
            reopened.elapsed(),
            blackhole.to_station(),
            blackhole.from_station()
        );
        if alice == bob {
            println!("converged {:?} after the path returned, at {alice:?}", reopened.elapsed());
            break;
        }
    }

    // An edit made now that the path is back: does *anything* still get
    // through from Alice to Bob?
    let before = host.texts().text(PARA).to_string();
    let afterwards = host.texts_mut().local_edit(PARA, &before, "Alice, online again.").expect("an edit");
    host.send_text(PARA.to_string(), afterwards, None);
    pump_for(host, joiner, Duration::from_secs(30)).await;
    let alice = host.texts().text(PARA);
    let bob = joiner.texts().text(PARA);
    println!("after an edit made once the path was back: alice {alice:?}, bob {bob:?}");

    assert_eq!(
        alice, bob,
        "an edit made while the path was closed is still lost {:?} later: alice {alice:?}, bob {bob:?}",
        AFTER
    );
}

/// The documents alone cannot say *where* the edit was lost: not arriving and
/// arriving-then-being-held look the same from the text. Watching the
/// transport on the receiving side separates them, because a message held by
/// the order buffer has already crossed it (rgfaber/craft-libs#2), and one
/// that is lost above the transport never does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn where_the_offline_edit_is_lost_is_visible_before_the_order_buffer() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut gap = open_gap(dir.path()).await;

    gap.blackhole.close();
    let alice_offline = gap.host.texts_mut().local_edit(PARA, "Alice writes.", "Alice, offline.").expect("an edit");
    gap.host.send_text(PARA.to_string(), alice_offline, None);
    let offline_seq = last_sent(&gap.alice_log).expect("the offline edit's sequence number");
    let bob_offline = gap.joiner.texts_mut().local_edit(PARA, "Alice writes.", "Bob, offline.").expect("an edit");
    gap.joiner.send_text(PARA.to_string(), bob_offline, None);
    pump_for(&mut gap.host, &mut gap.joiner, GAP).await;
    gap.blackhole.open();

    pump_for(&mut gap.host, &mut gap.joiner, AFTER).await;
    let alice_seen = first_author(&gap.bob_log);
    let delivered_offline = arrived(&gap.bob_log, &alice_seen, offline_seq);
    println!("{AFTER:?} after the path returned, Alice's seq {offline_seq} reached Bob: {delivered_offline}");
    println!("alice transport saw {}", entries(&gap.alice_log).join(", "));
    println!("bob transport saw {}", entries(&gap.bob_log).join(", "));

    // An edit from each side now that the path is back. Which of the two
    // arrives says which leg of the away node's path stopped carrying this
    // share's traffic: its own publishes out, or the station's to it.
    let before = gap.host.texts().text(PARA).to_string();
    let afterwards = gap.host.texts_mut().local_edit(PARA, &before, "Alice, online again.").expect("an edit");
    gap.host.send_text(PARA.to_string(), afterwards, None);
    let online_seq = last_sent(&gap.alice_log).expect("the later edit's sequence number");
    let bob_before = gap.joiner.texts().text(PARA).to_string();
    let bob_afterwards = gap.joiner.texts_mut().local_edit(PARA, &bob_before, "Bob, online again.").expect("an edit");
    gap.joiner.send_text(PARA.to_string(), bob_afterwards, None);
    let bob_seq = last_sent(&gap.bob_log).expect("Bob's later edit's sequence number");
    pump_for(&mut gap.host, &mut gap.joiner, Duration::from_secs(60)).await;

    let bob_seen = first_author(&gap.alice_log);
    let delivered_online = arrived(&gap.bob_log, &alice_seen, online_seq);
    let bob_to_alice = arrived(&gap.alice_log, &bob_seen, bob_seq);
    println!("edits made after the path returned: Alice's seq {online_seq} reached Bob: {delivered_online}; Bob's seq {bob_seq} reached Alice: {bob_to_alice}");
    println!("alice transport saw {}", entries(&gap.alice_log).join(", "));
    println!("bob transport saw {}", entries(&gap.bob_log).join(", "));

    let lost_where = match (delivered_offline, delivered_online, bob_to_alice) {
        (false, false, false) => "nothing crosses the away node's link any more, in either direction, though the connection is up",
        (false, false, true) => "the away node's publishes still reach the station, but nothing reaches it: the station's leg to it is dead",
        (false, true, _) => "only the edit made after the return arrived: one message was lost in transit",
        (true, false, _) => "the edit reached the away node and was never applied: its order buffer is holding it",
        (true, true, _) => "both reached the away node's transport",
    };
    println!("where it was lost: {lost_where}");

    let alice_text = gap.host.texts().text(PARA);
    let bob_text = gap.joiner.texts().text(PARA);
    assert_eq!(alice_text, bob_text, "the edit is lost — {lost_where}: alice {alice_text:?}, bob {bob_text:?}");
}
