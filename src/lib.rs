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

use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender};

use craft_collab::{Kind, Message, Transport};
use macula_rust::cbor::Value;
use macula_rust::node_key::NodeKey;
use macula_rust::pool::{Opts, Pool, Seed};
use macula_rust::profile::Profile;
use macula_rust::station_link::Publication;
use tokio::sync::mpsc::UnboundedSender;

/// Where text edits travel.
const TOPIC_TEXT: &str = "craft/collab/text_edited_v1";
/// Where cursor presence travels.
const TOPIC_CURSOR: &str = "craft/collab/cursor_moved_v1";
/// Where join snapshots travel.
const TOPIC_SHARED: &str = "craft/collab/document_shared_v1";

/// How to reach the shared document's realm: the seed station, the realm and
/// its key, and the crypto profile both sides run (`pq_pure` or `pq_hybrid`).
#[derive(Clone, Debug)]
pub struct MeshConfig {
    pub host: String,
    pub port: u16,
    /// The seed station's node id, as carried.
    pub station_node_id: [u8; 32],
    pub realm_id: [u8; 32],
    /// The realm's key as carried (advertisements are checked against it).
    pub realm_key: Vec<u8>,
    pub profile: String,
}

/// One node's view of a shared document, over the mesh.
pub struct MeshTransport {
    author: String,
    out: UnboundedSender<Outbound>,
    incoming: Receiver<Message>,
}

/// What the background thread publishes.
enum Outbound {
    Publish(&'static str, String),
}

impl MeshTransport {
    /// Connects this node to the mesh and starts listening. Returns once the
    /// first link is up, or the pool's connect timeout passes.
    pub fn connect(cfg: &MeshConfig) -> Result<MeshTransport, String> {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (in_tx, in_rx) = std::sync::mpsc::channel::<Message>();
        let cfg = cfg.clone();
        std::thread::Builder::new()
            .name("macula-craft-collab".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = ready_tx.send(Err(format!("runtime: {e}")));
                        return;
                    }
                };
                rt.block_on(run(cfg, in_tx, ready_tx));
            })
            .map_err(|e| format!("thread: {e}"))?;
        match ready_rx.recv() {
            Ok(Ok((author, out))) => Ok(MeshTransport {
                author,
                out,
                incoming: in_rx,
            }),
            Ok(Err(e)) => Err(e),
            Err(e) => Err(format!("the mesh thread ended before it was ready: {e}")),
        }
    }
}

/// Runs until the transport is dropped: then the outbound channel closes,
/// the loop ends and the pool closes.
async fn run(
    cfg: MeshConfig,
    in_tx: Sender<Message>,
    ready: std::sync::mpsc::Sender<Result<(String, UnboundedSender<Outbound>), String>>,
) {
    let profile = match Profile::parse(&cfg.profile) {
        Ok(p) => p,
        Err(e) => {
            let _ = ready.send(Err(format!("profile: {e}")));
            return;
        }
    };
    let key = match NodeKey::generate_identity(profile, macula_rust::node_key::PUZZLE_DIFFICULTY) {
        Ok(key) => key,
        Err(e) => {
            let _ = ready.send(Err(format!("identity: {e:?}")));
            return;
        }
    };
    let author = match key.node_id() {
        Ok(id) => hex::encode(id),
        Err(e) => {
            let _ = ready.send(Err(format!("identity: {e:?}")));
            return;
        }
    };
    let mut opts = Opts::new(Arc::new(key));
    opts.realm_trust.insert(cfg.realm_id, cfg.realm_key.clone());
    let seeds = vec![Seed {
        host: cfg.host.clone(),
        port: cfg.port,
        node_id: cfg.station_node_id,
    }];
    let pool = match Pool::connect(seeds, opts).await {
        Ok(pool) => pool,
        Err(e) => {
            let _ = ready.send(Err(format!("connect: {e:?}")));
            return;
        }
    };

    let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel::<Outbound>();
    for topic in [TOPIC_TEXT, TOPIC_CURSOR, TOPIC_SHARED] {
        let Ok(mut sub) = pool.subscribe(&cfg.realm_id, topic).await else {
            let _ = ready.send(Err(format!("subscribe {topic}")));
            return;
        };
        let tx = in_tx.clone();
        tokio::spawn(async move {
            while let Some(event) = sub.recv().await {
                let json = event.payload.get("json").and_then(|v| match v {
                    Value::Text(t) => Some(t.clone()),
                    _ => None,
                });
                if let Some(json) = json
                    && let Ok(msg) = serde_json::from_str::<Message>(&json)
                    && tx.send(msg).is_err()
                {
                    break;
                }
            }
        });
    }
    // The transport holds the only sender; when it drops, the channel ends.
    let _ = ready.send(Ok((author, out_tx)));

    let realm = cfg.realm_id;
    while let Some(out) = out_rx.recv().await {
        match out {
            Outbound::Publish(topic, json) => {
                let payload = Value::Map(vec![(Value::text("json"), Value::text(json))]);
                let _ = pool
                    .publish(Publication {
                        realm,
                        topic: topic.to_string(),
                        payload,
                        ttl_ms: None,
                    })
                    .await;
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
        self.out
            .send(Outbound::Publish(topic, json))
            .map_err(|_| "the mesh link has ended".to_string())
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
        Kind::SnapshotRequest {} | Kind::Snapshot { .. } => TOPIC_SHARED,
    }
}
