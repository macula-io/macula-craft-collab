//! The Macula mesh transport for the shared Craft collaboration seam.
//!
//! Implements [`craft_collab::Transport`] over macula-rust (released crates
//! only): document text edits, cursor presence and the join snapshot travel
//! as signed mesh publications in a realm, and the pool runs on a background
//! thread while the app stays synchronous.
//!
//! **A shared document travels sealed.** Every message is published under the
//! document's share group — a topic prefix the host mints per session,
//! `<realm>/~<host>/craft/<share>` — and sealed under that group's current
//! epoch, so a realm member without the grant and a station relaying it see
//! ciphertext and nothing else (`macula-craft-collab#26`, threat model: a
//! shared document is readable only by its holders). The topic names below are
//! the last segment of each topic; the share's prefix comes first, so every
//! topic is the five segments `macula_topic` validates. There is no clear path
//! in this crate: a publication that is not under a sealed group is a bug, not
//! a fallback.

pub mod craft_mesh;
pub mod grant;
pub mod identity;
pub mod issuer;
pub mod realm;

pub use craft_mesh::{CraftMesh, DEFAULT_REALM};
pub use grant::{KeyGrantVerifier, sign_grant, verified_access, verified_access_from, verify_grant};
pub use identity::Identity;
pub use issuer::{IdentityIssuer, verify_invite};
pub use realm::trust::{RealmDescriptor, RealmTrust, TrustedRealm};
pub use realm::{RealmCredential, RealmMemberVerifier, Tier};

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};

use craft_collab::{Kind, Message, Transport};
use macula_rust::cbor::Value;
use macula_rust::frame::Payload;
use macula_rust::group::{Group, Reason};
use macula_rust::node_key::NodeKey;
use macula_rust::pool::{Opts, Pool, Seed, Subscription};
use macula_rust::station_link::Event;
use tokio::sync::mpsc::UnboundedSender;

/// Where text edits travel, after the share's prefix.
const NAME_TEXT: &str = "text_edited_v1";
/// Where cursor presence travels.
const NAME_CURSOR: &str = "cursor_moved_v1";
/// Where join snapshots travel.
const NAME_SHARED: &str = "document_shared_v1";
/// Where command ops travel.
const NAME_COMMAND: &str = "command_applied_v1";
/// Where join requests travel.
const NAME_JOIN: &str = "join_requested_v1";
/// Where issued grants travel.
const NAME_GRANT: &str = "grant_issued_v1";
/// Where revocations travel.
const NAME_REVOKE: &str = "holder_revoked_v1";

/// Every topic a share carries, by its last segment.
const NAMES: [&str; 7] = [NAME_TEXT, NAME_CURSOR, NAME_SHARED, NAME_COMMAND, NAME_JOIN, NAME_GRANT, NAME_REVOKE];

/// How the session is placed in its group: the prefix its topics hang under,
/// the UCAN that pulls the group's key (minted with the grant, refused by the
/// distributor to anyone else), and the node that must be its distributor —
/// the host, pinned by the invite.
#[derive(Clone, Debug, Default)]
pub struct Share {
    /// The group's whole prefix, `<realm>/<org>/<app>/<domain>`. Empty when
    /// this node is the host and mints one at connect.
    pub prefix: String,
    /// The group grant: what the distributor is shown on every key pull.
    pub grant: Vec<u8>,
    /// The node the distributor must be. `None` takes the first answer the
    /// keyring is offered, which only a plain test does.
    pub distributor: Option<[u8; 32]>,
}

/// How to reach the shared document's realm: the seed station and the realm.
/// The identity (key and node id) comes from [`Identity`].
#[derive(Clone, Debug)]
pub struct MeshConfig {
    pub host: String,
    pub port: u16,
    /// The seed station's node id, as carried.
    pub station_node_id: [u8; 32],
    pub realm_id: [u8; 32],
    /// The realm's key as carried (advertisements are checked against it);
    /// empty trusts nothing, which pubsub does not need.
    pub realm_key: Vec<u8>,
    /// The realm's *name* — `io.macula` — which is a group prefix's first
    /// segment. The realm id above is a hex id and does not belong in a topic.
    pub realm_name: String,
    /// The share this transport carries.
    pub share: Share,
}

/// One node's view of a shared document, over the mesh.
pub struct MeshTransport {
    author: String,
    /// The share's group prefix: what this node carries, whether it minted it
    /// or was given it by an invite.
    prefix: String,
    out: UnboundedSender<Outbound>,
    incoming: Receiver<Message>,
    /// Messages dropped because their claimed author was not the verified
    /// publisher (a forged envelope author).
    dropped_unverified: Arc<AtomicU64>,
    arrivals: Arrivals,
    /// This node's current membership UCAN of the transport's realm, kept
    /// renewed by the mesh thread (macula-realm#46).
    membership: Arc<Mutex<Option<String>>>,
}

/// What became of the events a share's topics delivered that could not be
/// handed to the seam, counted rather than swallowed: an application shows
/// these, and a test asserts on them. The same discipline as
/// [`MeshTransport::dropped_unverified`], for the three new ways an event is
/// refused.
#[derive(Clone, Default)]
struct Arrivals {
    /// Sealed events that did not open: another epoch's key, a routing field
    /// other than the one they were sealed with, or a changed byte.
    unopened: Arc<AtomicU64>,
    /// Why the last of those did not open.
    last_unopened: Arc<Mutex<Option<Reason>>>,
    /// Events that arrived *clear* under the share's prefix. The group's
    /// policy is `required`, so the pool refuses these before they reach us;
    /// this crate refuses its own copy anyway, because only `required` gives
    /// that for free and this count is how a regression would show.
    clear_refused: Arc<AtomicU64>,
}

impl MeshTransport {
    /// How many inbound messages were dropped because their envelope author
    /// was not the publication's verified publisher.
    pub fn dropped_unverified(&self) -> u64 {
        self.dropped_unverified.load(Ordering::Relaxed)
    }

    /// How many sealed events arrived that could not be opened. None is
    /// applied and none is dropped silently: an application shows the count
    /// and retries its pull.
    pub fn unopened(&self) -> u64 {
        self.arrivals.unopened.load(Ordering::Relaxed)
    }

    /// Why the most recent of those did not open.
    pub fn last_unopened(&self) -> Option<Reason> {
        self.arrivals.last_unopened.lock().ok().and_then(|r| *r)
    }

    /// How many events arrived clear under the share's prefix and were
    /// refused: zero in a correct session.
    pub fn clear_refused(&self) -> u64 {
        self.arrivals.clear_refused.load(Ordering::Relaxed)
    }

    /// The share's group prefix: the host's minted one, or the one an invite
    /// named. Every topic this session publishes under starts with it.
    pub fn group_prefix(&self) -> &str {
        &self.prefix
    }
}

/// What the background thread publishes.
enum Outbound {
    Publish(String, String),
    /// A realm device-tier join, run on the transport's own pool; the
    /// answer carries the credential (already stored here on success).
    DeviceJoin {
        realm_name: String,
        reply: std::sync::mpsc::SyncSender<Result<RealmCredential, String>>,
    },
}

impl MeshTransport {
    /// Connects this node to the mesh, as `identity`, and starts listening on
    /// its share's topics. Returns once every subscription is up, or the
    /// pool's connect timeout passes.
    ///
    /// A host (no prefix in the share) mints one here; a joiner is given the
    /// prefix by its invite and must already hold the group's grant, because
    /// the key pull happens before the join request it is asked for.
    pub fn connect(cfg: &MeshConfig, identity: &Identity) -> Result<MeshTransport, String> {
        let prefix = match cfg.share.prefix.is_empty() {
            true => mint_prefix(&cfg.realm_name, identity.node_id())?,
            false => cfg.share.prefix.clone(),
        };
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (in_tx, in_rx) = std::sync::mpsc::channel::<Message>();
        let cfg = cfg.clone();
        let author = identity.node_id().to_string();
        let key = identity.key();
        let group = Group { prefix: prefix.clone(), ucan: cfg.share.grant.clone(), distributor: cfg.share.distributor };
        let identity = identity.clone();
        let dropped = Arc::new(AtomicU64::new(0));
        let dropped_in_thread = dropped.clone();
        let arrivals = Arrivals::default();
        let arrivals_in_thread = arrivals.clone();
        let membership = Arc::new(Mutex::new(None));
        let membership_in_thread = membership.clone();
        std::thread::Builder::new()
            .name("macula-craft-collab".into())
            .spawn(move || {
                run_on_new_runtime(cfg, key, identity, group, in_tx, ready_tx, dropped_in_thread, arrivals_in_thread, membership_in_thread);
            })
            .map_err(|e| format!("thread: {e}"))?;
        match ready_rx.recv() {
            Ok(Ok(out)) => Ok(MeshTransport { author, prefix, out, incoming: in_rx, dropped_unverified: dropped, arrivals, membership }),
            Ok(Err(e)) => Err(e),
            Err(e) => Err(format!("the mesh thread ended before it was ready: {e}")),
        }
    }
}

/// The share prefix a host mints: `<realm>/~<host>/craft/<share>`, the share
/// id random and per session. Random and not derived from the document, so a
/// document's permanent id never appears in a topic the realm can see, and
/// per session, so yesterday's topics are gone when sharing starts again.
fn mint_prefix(realm_name: &str, host_hex: &str) -> Result<String, String> {
    let mut id = [0u8; 16];
    getrandom::getrandom(&mut id).map_err(|e| format!("no randomness for a share id: {e}"))?;
    let share: String = id.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("{realm_name}/~{host_hex}/craft/{share}"))
}

impl MeshTransport {
    /// A silent device-tier join of `realm_name` through this transport's
    /// own pool: proves the key, asks the realm for a membership, stores
    /// the credential beside the identity keys. Blocking; call it from a
    /// worker thread (the UI does) or at startup.
    pub fn join_realm_device(&self, realm_name: &str) -> Result<RealmCredential, String> {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        self.out
            .send(Outbound::DeviceJoin { realm_name: realm_name.to_string(), reply: tx })
            .map_err(|_| "the mesh transport is closed".to_string())?;
        rx.recv().map_err(|_| "the mesh transport ended before the join answered".to_string())?
    }
}

/// The knobs the mesh thread runs on, kept in one place so the runtime
/// builder and the loop do not drift apart.
struct MeshThread {
    cfg: MeshConfig,
    key: Arc<NodeKey>,
    identity: Identity,
    group: Group,
    ready: std::sync::mpsc::Sender<Result<UnboundedSender<Outbound>, String>>,
    dropped: Arc<AtomicU64>,
    arrivals: Arrivals,
    membership: Arc<Mutex<Option<String>>>,
}

/// Builds the mesh thread's runtime and runs the transport loop on it. A
/// runtime that cannot be built is reported where a failed connect is.
#[allow(clippy::too_many_arguments)]
fn run_on_new_runtime(
    cfg: MeshConfig,
    key: Arc<NodeKey>,
    identity: Identity,
    group: Group,
    in_tx: Sender<Message>,
    ready: std::sync::mpsc::Sender<Result<UnboundedSender<Outbound>, String>>,
    dropped: Arc<AtomicU64>,
    arrivals: Arrivals,
    membership: Arc<Mutex<Option<String>>>,
) {
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = ready.send(Err(format!("runtime: {e}")));
            return;
        }
    };
    let thread = MeshThread { cfg, key, identity, group, ready, dropped, arrivals, membership };
    rt.block_on(run(thread, in_tx));
}

/// Runs until the transport is dropped: then the outbound channel closes,
/// the loop ends and the pool closes.
async fn run(thread: MeshThread, in_tx: Sender<Message>) {
    let MeshThread { cfg, key, identity, group, ready, dropped, arrivals, membership } = thread;
    let mut opts = Opts::new(key);
    // Pubsub needs no realm trust: it is only consulted when a call resolves
    // an advertisement. An empty key means "trust nothing in this realm".
    if !cfg.realm_key.is_empty() {
        opts.realm_trust.insert(cfg.realm_id, cfg.realm_key.clone());
    }
    let seeds = vec![Seed { host: cfg.host.clone(), port: cfg.port, node_id: cfg.station_node_id }];
    let pool = match Pool::connect(seeds, opts).await {
        Ok(pool) => pool,
        Err(e) => {
            let _ = ready.send(Err(format!("connect: {e:?}")));
            return;
        }
    };

    // The realm membership, kept renewed while the transport runs: the
    // silent device-tier join at first connect (opt-in,
    // MACULA_CRAFT_AUTOJOIN_REALM), then every stored membership of this
    // realm renewed before its 1 hour token runs out (macula-realm#46). Only
    // when a realm key is pinned: a call can only be resolved under it.
    // Non-fatal by design.
    if cfg.realm_key.is_empty() {
        if realm::auto_join_realm().is_some() {
            eprintln!("realm auto-join: no realm key pinned in this config; skipping (calls need the trust anchor)");
        }
    } else {
        tokio::spawn(realm::keep_memberships_renewed(pool.clone(), identity.clone(), cfg.realm_id, membership));
    }

    let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel::<Outbound>();
    for name in NAMES {
        let topic = topic_of(&group.prefix, name);
        // Subscribing under the group joins it first, so the key is pulled
        // before this session can publish anything: a joiner has its key
        // before it knocks. A group whose key cannot be had fails here rather
        // than falling back to the clear.
        let Ok(sub) = pool.subscribe_group(&cfg.realm_id, &topic, &group).await else {
            let _ = ready.send(Err(format!("subscribe {topic}")));
            return;
        };
        let tx = in_tx.clone();
        let arrivals = arrivals.clone();
        tokio::spawn(pump_events(sub, tx, dropped.clone(), arrivals));
    }
    // The transport holds the only sender; when it drops, the channel ends.
    let _ = ready.send(Ok(out_tx));

    let realm = cfg.realm_id;
    while let Some(out) = out_rx.recv().await {
        match out {
            Outbound::DeviceJoin { realm_name, reply } => {
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
                // Through the renewal path, so a person's stored fields stay.
                let _ = reply.send(realm::renew_membership(&pool, &identity, &realm_name, now).await);
            }
            Outbound::Publish(topic, json) => publish_sealed(&pool, realm, &group, topic, json).await,
        }
    }
    pool.close().await;
}

/// Publishes one message sealed under the share's group.
///
/// There is no clear arm on purpose: a publication that is not under the
/// group is refused rather than sent in the open. A publication that fails —
/// the publisher's epochs have all stopped publishing and the pull that would
/// renew them failed — is reported and not sent: the seam sees the message
/// never left, and the app's waiting state (`no_distributor`) is what it
/// shows. Never a clear fallback.
async fn publish_sealed(pool: &Pool, realm: [u8; 32], group: &Group, topic: String, json: String) {
    let payload = Value::Map(vec![(Value::text("json"), Value::text(json))]);
    if let Err(e) = pool.publish_group(&realm, &topic, group, payload).await {
        eprintln!("craft-collab: {topic} was not published: {e:?}");
    }
}

/// The topic a message's kind travels on, under the share's prefix.
fn topic_of(prefix: &str, name: &str) -> String {
    format!("{prefix}/{name}")
}

/// Feeds a subscription's events to the transport until the transport drops
/// its receiving end or the subscription ends.
async fn pump_events(mut sub: Subscription, tx: Sender<Message>, dropped: Arc<AtomicU64>, arrivals: Arrivals) {
    while let Some(event) = sub.recv().await {
        if !deliver_event(&event, &tx, &dropped, &arrivals) {
            break;
        }
    }
}

/// Hands one delivered event to the transport as a message, or counts it as
/// one of the ways an event can be refused; false when the receiving end has
/// closed.
fn deliver_event(event: &Event, tx: &Sender<Message>, dropped: &Arc<AtomicU64>, arrivals: &Arrivals) -> bool {
    // A sealed event that did not open arrives with no payload and the reason
    // it failed. It is counted and never applied: the alternative is a
    // ciphertext treated as a payload.
    if let Some(reason) = event.unopened {
        arrivals.unopened.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut last) = arrivals.last_unopened.lock() {
            *last = Some(reason);
        }
        return true;
    }
    // The publication's verified publisher: the envelope author
    // must be exactly this, or the message is a forgery and is
    // dropped, never trusted.
    let publisher: String = event.publisher.iter().map(|b| format!("{b:02x}")).collect();
    let json = match &event.payload {
        // A clear event has no place under a share the group was required
        // for: the pool refuses one, and this refuses it too rather than
        // trust the policy alone.
        Payload::Clear(_) if event.seal_key_id.is_none() => {
            arrivals.clear_refused.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        Payload::Clear(value) => value.get("json").and_then(|v| match v {
            Value::Text(t) => Some(t.clone()),
            _ => None,
        }),
        // Not the shape a pool subscription delivers, which marks
        // a sealed event unopened and clears its payload; matched
        // so the payload is read whole.
        Payload::Sealed(_) => None,
    };
    let Some(json) = json else {
        return true;
    };
    match verified_message(&json, &publisher) {
        Some(msg) => tx.send(msg).is_ok(),
        None => {
            dropped.fetch_add(1, Ordering::Relaxed);
            true
        }
    }
}

impl Transport for MeshTransport {
    fn author(&self) -> String {
        self.author.clone()
    }

    fn send(&mut self, msg: Message) -> Result<(), String> {
        let name = name_for(&msg.kind);
        let topic = topic_of(&self.prefix, name);
        let json = serde_json::to_string(&msg).map_err(|e| e.to_string())?;
        self.out.send(Outbound::Publish(topic, json)).map_err(|_| "the mesh link has ended".to_string())
    }

    fn poll(&mut self) -> Vec<Message> {
        self.incoming.try_iter().collect()
    }

    fn membership(&self) -> Option<String> {
        self.membership.lock().ok()?.clone()
    }
}

/// The last segment of the topic a message's kind travels on.
fn name_for(kind: &Kind) -> &'static str {
    match kind {
        Kind::TextEdit { .. } => NAME_TEXT,
        Kind::CursorMoved { .. } => NAME_CURSOR,
        Kind::Command { .. } => NAME_COMMAND,
        Kind::JoinRequest { .. } => NAME_JOIN,
        Kind::GrantIssued { .. } => NAME_GRANT,
        Kind::Revoked { .. } => NAME_REVOKE,
        Kind::SnapshotRequest {} | Kind::Snapshot { .. } => NAME_SHARED,
    }
}

/// A payload message, only when its envelope author is the verified
/// publisher the transport saw; `None` for a message claiming another's id.
pub fn verified_message(json: &str, publisher_hex: &str) -> Option<Message> {
    let msg: Message = serde_json::from_str(json).ok()?;
    (msg.author == publisher_hex).then_some(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg_json(author: &str) -> String {
        serde_json::to_string(&Message {
            doc: "demo".into(),
            author: author.into(),
            epoch: 7,
            seq: 1,
            sent_at_ms: 0,
            kind: Kind::CursorMoved { position: None, name: None },
        })
        .expect("json")
    }

    fn event(payload: Payload, seal_key_id: Option<[u8; 8]>, unopened: Option<Reason>) -> Event {
        Event {
            publisher: [3u8; 32],
            realm: [7u8; 32],
            topic: "io.macula/~aa/craft/9f9f/text_edited_v1".into(),
            seq: 1,
            published_at: 0,
            payload,
            delivered_via: String::new(),
            seal_key_id,
            unopened,
        }
    }

    fn arriving() -> (Sender<Message>, Receiver<Message>) {
        std::sync::mpsc::channel()
    }

    fn publishable(json: &str) -> Payload {
        Payload::Clear(Value::Map(vec![(Value::text("json"), Value::text(json))]))
    }

    #[test]
    fn the_verified_publisher_authors_its_messages() {
        let json = msg_json("aabbcc");
        let msg = verified_message(&json, "aabbcc").expect("the publisher's own message");
        assert_eq!(msg.author, "aabbcc");
    }

    #[test]
    fn an_author_that_is_not_the_publisher_is_refused() {
        let json = msg_json("aabbcc");
        assert!(verified_message(&json, "112233").is_none(), "a claimed author that is not the verified publisher is a forgery");
        assert!(verified_message("not json", "aabbcc").is_none());
    }

    /// Every topic a share carries is five segments, which is what
    /// `macula_topic` validates, and none of them is the document's id.
    #[test]
    fn a_shares_topics_are_five_segments_under_its_prefix() {
        let prefix = "io.macula/~aaaa/craft/9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f";
        for name in NAMES {
            let topic = topic_of(prefix, name);
            assert_eq!(topic.split('/').count(), 5, "{topic} is five segments");
            assert!(topic.starts_with(&format!("{prefix}/")), "{topic} hangs under the share");
        }
    }

    /// A host mints a random share id per session and never derives the
    /// prefix from the document, so no permanent id can appear in a topic.
    #[test]
    fn a_minted_prefix_is_random_and_names_the_host() {
        let host = "ab".repeat(32);
        let first = mint_prefix("io.macula", &host).expect("a share id");
        let second = mint_prefix("io.macula", &host).expect("a share id");
        assert_ne!(first, second, "a fresh share id per session");
        assert!(first.starts_with("io.macula/~abab"), "the host is in the org slot: {first}");
        assert_eq!(first.split('/').count(), 4, "{first} is a four-segment prefix");
    }

    /// An event that did not open is counted with its reason, and the seam
    /// never sees it: nothing is applied, nothing is dropped silently.
    #[test]
    fn an_unopened_event_is_counted_and_not_delivered() {
        let (tx, rx) = arriving();
        let dropped = Arc::new(AtomicU64::new(0));
        let arrivals = Arrivals::default();
        let event = event(Payload::Clear(Value::Null), Some([1u8; 8]), Some(Reason::UnknownEpoch));
        assert!(deliver_event(&event, &tx, &dropped, &arrivals), "the pump carries on");
        assert!(rx.try_recv().is_err(), "the seam is handed nothing");
        assert_eq!(arrivals.unopened.load(Ordering::Relaxed), 1);
        assert_eq!(arrivals.last_unopened.lock().unwrap().as_ref(), Some(&Reason::UnknownEpoch));
    }

    /// A clear event under the share's prefix is refused here as well as by
    /// the group's `required` policy: a regression that loosened the policy
    /// would still not put a document in the open.
    #[test]
    fn a_clear_event_is_refused_and_never_delivered() {
        let (tx, rx) = arriving();
        let dropped = Arc::new(AtomicU64::new(0));
        let arrivals = Arrivals::default();
        let event = event(publishable(&msg_json("0303030303")), None, None);
        assert!(deliver_event(&event, &tx, &dropped, &arrivals));
        assert!(rx.try_recv().is_err(), "a clear event is never handed to the seam");
        assert_eq!(arrivals.clear_refused.load(Ordering::Relaxed), 1);
    }

    /// A sealed event that opened is delivered, and its forged author is
    /// still refused: sealing adds a check, it removes none.
    #[test]
    fn an_opened_event_still_answers_its_author() {
        let (tx, rx) = arriving();
        let dropped = Arc::new(AtomicU64::new(0));
        let arrivals = Arrivals::default();
        let forged = msg_json("aabbcc");
        let event = event(publishable(&forged), Some([2u8; 8]), None);
        assert!(deliver_event(&event, &tx, &dropped, &arrivals));
        assert!(rx.try_recv().is_err(), "a forged author is not delivered");
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        assert_eq!(arrivals.clear_refused.load(Ordering::Relaxed), 0, "an opened event is not a clear one");
    }
}
