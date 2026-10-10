//! The Macula mesh transport for the shared Craft collaboration seam.
//!
//! Implements [`craft_collab::Transport`] over macula-rust (released crates
//! only): document text edits, cursor presence and the join snapshot travel
//! as signed mesh publications in a realm, and the pool runs on a background
//! thread while the app stays synchronous.
//!
//! Topics: `craft/collab/text_edited_v1`, `craft/collab/cursor_moved_v1` and
//! `craft/collab/document_shared_v1`; the document id, author and payload are
//! in the message itself.

pub mod grant;
pub mod identity;
pub mod issuer;
pub mod realm;

pub use grant::{KeyGrantVerifier, sign_grant, verified_access, verified_access_from, verify_grant};
pub use identity::Identity;
pub use issuer::{IdentityIssuer, verify_invite};
pub use realm::{RealmCredential, RealmMemberVerifier, Tier};

use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender};

use craft_collab::{Kind, Message, Transport};
use macula_rust::cbor::Value;
use macula_rust::node_key::NodeKey;
use macula_rust::pool::{Opts, Pool, Seed};
use macula_rust::station_link::Publication;
use tokio::sync::mpsc::UnboundedSender;

/// Where text edits travel.
const TOPIC_TEXT: &str = "craft/collab/text_edited_v1";
/// Where cursor presence travels.
const TOPIC_CURSOR: &str = "craft/collab/cursor_moved_v1";
/// Where join snapshots travel.
const TOPIC_SHARED: &str = "craft/collab/document_shared_v1";
/// Where replayed commands travel.
/// Where command ops travel.
const TOPIC_COMMAND: &str = "craft/collab/command_applied_v1";
/// Where join requests travel.
const TOPIC_JOIN: &str = "craft/collab/join_requested_v1";
/// Where issued grants travel.
const TOPIC_GRANT: &str = "craft/collab/grant_issued_v1";
/// Where revocations travel.
const TOPIC_REVOKE: &str = "craft/collab/holder_revoked_v1";

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
}

/// One node's view of a shared document, over the mesh.
pub struct MeshTransport {
    author: String,
    out: UnboundedSender<Outbound>,
    incoming: Receiver<Message>,
    /// Messages dropped because their claimed author was not the verified
    /// publisher (a forged envelope author).
    dropped_unverified: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl MeshTransport {
    /// How many inbound messages were dropped because their envelope author
    /// was not the publication's verified publisher.
    pub fn dropped_unverified(&self) -> u64 {
        self.dropped_unverified.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// What the background thread publishes.
enum Outbound {
    Publish(&'static str, String),
    /// A realm device-tier join, run on the transport's own pool; the
    /// answer carries the credential (already stored here on success).
    DeviceJoin {
        realm_name: String,
        reply: std::sync::mpsc::SyncSender<Result<RealmCredential, String>>,
    },
}

impl MeshTransport {
    /// Connects this node to the mesh, as `identity`, and starts listening.
    /// Returns once the first link is up, or the pool's connect timeout
    /// passes.
    pub fn connect(cfg: &MeshConfig, identity: &Identity) -> Result<MeshTransport, String> {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (in_tx, in_rx) = std::sync::mpsc::channel::<Message>();
        let cfg = cfg.clone();
        let author = identity.node_id().to_string();
        let key = identity.key();
        let identity = identity.clone();
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let dropped_in_thread = dropped.clone();
        std::thread::Builder::new()
            .name("macula-craft-collab".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = ready_tx.send(Err(format!("runtime: {e}")));
                        return;
                    }
                };
                rt.block_on(run(cfg, key, identity, in_tx, ready_tx, dropped_in_thread));
            })
            .map_err(|e| format!("thread: {e}"))?;
        match ready_rx.recv() {
            Ok(Ok(out)) => Ok(MeshTransport { author, out, incoming: in_rx, dropped_unverified: dropped }),
            Ok(Err(e)) => Err(e),
            Err(e) => Err(format!("the mesh thread ended before it was ready: {e}")),
        }
    }
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

/// Runs until the transport is dropped: then the outbound channel closes,
/// the loop ends and the pool closes.
async fn run(
    cfg: MeshConfig,
    key: Arc<NodeKey>,
    identity: Identity,
    in_tx: Sender<Message>,
    ready: std::sync::mpsc::Sender<Result<UnboundedSender<Outbound>, String>>,
    dropped: std::sync::Arc<std::sync::atomic::AtomicU64>,
) {
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

    // The silent device-tier realm membership, at first connect: opt-in
    // (MACULA_CRAFT_AUTOJOIN_REALM) and only when a realm key is pinned
    // (a call can only be resolved under it). Non-fatal by design.
    if cfg.realm_key.is_empty() {
        if realm::auto_join_realm().is_some() {
            eprintln!("realm auto-join: no realm key pinned in this config; skipping (calls need the trust anchor)");
        }
    } else {
        let pool_for_join = pool.clone();
        let identity_for_join = identity.clone();
        tokio::spawn(async move {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
            realm::ensure_auto_join(&pool_for_join, &identity_for_join, now).await;
        });
    }

    let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel::<Outbound>();
    for topic in [TOPIC_TEXT, TOPIC_CURSOR, TOPIC_SHARED, TOPIC_COMMAND, TOPIC_JOIN, TOPIC_GRANT, TOPIC_REVOKE] {
        let Ok(mut sub) = pool.subscribe(&cfg.realm_id, topic).await else {
            let _ = ready.send(Err(format!("subscribe {topic}")));
            return;
        };
        let tx = in_tx.clone();
        let dropped = dropped.clone();
        tokio::spawn(async move {
            while let Some(event) = sub.recv().await {
                // The publication's verified publisher: the envelope author
                // must be exactly this, or the message is a forgery and is
                // dropped, never trusted.
                let publisher: String = event.publisher.iter().map(|b| format!("{b:02x}")).collect();
                let json = event.payload.get("json").and_then(|v| match v {
                    Value::Text(t) => Some(t.clone()),
                    _ => None,
                });
                if let Some(json) = json {
                    match verified_message(&json, &publisher) {
                        Some(msg) => {
                            if tx.send(msg).is_err() {
                                break;
                            }
                        }
                        None => {
                            dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                }
            }
        });
    }
    // The transport holds the only sender; when it drops, the channel ends.
    let _ = ready.send(Ok(out_tx));

    let realm = cfg.realm_id;
    while let Some(out) = out_rx.recv().await {
        match out {
            Outbound::DeviceJoin { realm_name, reply } => {
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
                let outcome = match realm::join_device(&pool, &identity, &realm_name, now).await {
                    Ok(cred) => match realm::store_credential(&cred) {
                        Ok(_) => Ok(cred),
                        Err(e) => Err(e),
                    },
                    Err(e) => Err(e),
                };
                let _ = reply.send(outcome);
            }
            Outbound::Publish(topic, json) => {
                let payload = Value::Map(vec![(Value::text("json"), Value::text(json))]);
                let _ = pool.publish(Publication { realm, topic: topic.to_string(), payload, ttl_ms: None }).await;
            }
        }
    }
    pool.close().await;
}

impl Transport for MeshTransport {
    fn author(&self) -> String {
        self.author.clone()
    }

    fn send(&mut self, msg: Message) -> Result<(), String> {
        let topic = topic_for(&msg.kind);
        let json = serde_json::to_string(&msg).map_err(|e| e.to_string())?;
        self.out.send(Outbound::Publish(topic, json)).map_err(|_| "the mesh link has ended".to_string())
    }

    fn poll(&mut self) -> Vec<Message> {
        self.incoming.try_iter().collect()
    }
}

/// The topic a message's kind travels on.
fn topic_for(kind: &Kind) -> &'static str {
    match kind {
        Kind::TextEdit { .. } => TOPIC_TEXT,
        Kind::CursorMoved { .. } => TOPIC_CURSOR,
        Kind::Command { .. } => TOPIC_COMMAND,
        Kind::JoinRequest { .. } => TOPIC_JOIN,
        Kind::GrantIssued { .. } => TOPIC_GRANT,
        Kind::Revoked { .. } => TOPIC_REVOKE,
        Kind::SnapshotRequest {} | Kind::Snapshot { .. } => TOPIC_SHARED,
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
}
