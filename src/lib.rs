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
pub mod roster;

pub use craft_mesh::{CraftMesh, DEFAULT_REALM};
pub use grant::{KeyGrantVerifier, sign_grant, verified_access, verified_access_from, verify_grant};
pub use identity::Identity;
pub use issuer::{GROUP_CREDENTIAL_MS, IdentityIssuer, verify_invite};
pub use realm::trust::{RealmDescriptor, RealmTrust, TrustedRealm};
pub use realm::{RealmCredential, RealmMemberVerifier, Tier};
pub use roster::Roster;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};

use craft_collab::{Kind, Message, Transport};
use macula_rust::cbor::Value;
use macula_rust::frame::Payload;
use macula_rust::group::{Distributor, DistributorOptions, Group, MembershipCheck, Policy, Reason, RemovedCheck, org_of};
use macula_rust::node_key::{NodeKey, key_id_of};
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
#[derive(Clone)]
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
    /// Whether this node is the share's host: it mints the prefix (when the
    /// share names none) and serves the share's key distributor. A joiner is
    /// given its prefix and credential by the invite and serves nothing.
    pub hosting: bool,
    /// The host's answer to "may this node hold the share group's key",
    /// consulted by the distributor this node serves. Closures, so the
    /// transport never names the host's record's type; `None` on a joiner,
    /// which serves nothing — and on a host that would then serve no
    /// distributor, so the share fails closed rather than travels unsealed.
    pub membership: Option<MembershipCheck>,
    /// The host's answer to "has this node been removed for good": revoked,
    /// with no grant newer than the revocation. Absolute: asked before the
    /// membership check and again after it.
    pub removed: Option<RemovedCheck>,
}

impl std::fmt::Debug for MeshConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("station_node_id", &self.station_node_id)
            .field("realm_id", &self.realm_id)
            .field("realm_name", &self.realm_name)
            .field("share", &self.share)
            .field("hosting", &self.hosting)
            .field("host_checks", &(self.membership.is_some() && self.removed.is_some()))
            .finish()
    }
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
    /// Why the share is not usable yet, when it is not: the key distributor
    /// has not answered, and every publication is refused until it does.
    waiting: Arc<Mutex<Option<Reason>>>,
    /// What the pool that owns this transport's link counts as accepted and
    /// not delivered ([`Pool::unsent_publications`]): the case where the
    /// station took the publication but the link ended before it was known to
    /// have read it, and no link took it again in time (macula-craft-collab#38).
    /// Asked of the pool rather than copied, so the number is the pool's own.
    pool_unsent: PoolUnsent,
}

/// How a transport asks its pool what it accepted and could not deliver. A
/// closure, not the pool: the sum in
/// [`MeshTransport::refused_publications`] then has a test that sets the
/// number itself, instead of waiting out a publication's fifteen-minute
/// acceptance window.
type PoolUnsent = Arc<dyn Fn() -> u64 + Send + Sync>;

/// What the mesh thread hands back once the transport is ready to be used:
/// the outbound channel, and the pool's own count for what it could not
/// deliver.
struct Ready {
    out: UnboundedSender<Outbound>,
    pool_unsent: PoolUnsent,
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
    /// Events that were opened and then discarded because they carried no
    /// message this crate could use (a payload that is not `{"json": Text}`).
    unusable: Arc<AtomicU64>,
    /// Messages **this** node tried to publish and the mesh refused, for any
    /// reason. Nothing is sent in the clear instead, so this is the number
    /// that says an edit did not leave: an application shows it and the two
    /// copies are known to differ rather than silently going their own way.
    refused_outbound: Arc<AtomicU64>,
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

    /// How many events this share opened and then could not use: the payload
    /// carried no message. Counted rather than dropped quietly, like the
    /// three inbound refusals beside it.
    pub fn unusable(&self) -> u64 {
        self.arrivals.unusable.load(Ordering::Relaxed)
    }

    /// How many of this node's own publications did not leave, from both
    /// sources that know: what the mesh refused before anything was sent
    /// (nothing is ever sent in the clear instead, so this is never a message
    /// that became readable), and what the pool accepted and then could not
    /// deliver because its link ended first — its own
    /// [`Pool::unsent_publications`], counted there and read here.
    ///
    /// A non-zero count means a **publication** did not leave — this transport
    /// carries cursor moves as well as edits, and the number carries neither a
    /// kind nor a message id, so it does not say which one was lost. An app
    /// should word what it tells the person accordingly: "something you sent
    /// may not have reached the others", not "your edit was lost". Telling the
    /// two apart would take a per-kind counter, which this transport does not
    /// keep (`waiting()` is set as well when the reason is about the share
    /// rather than the message).
    ///
    /// What is *not* in it: a publication the station took and answered for,
    /// that no subscriber then read. The wire acknowledges no PUBLISH, so
    /// nothing here or in the pool can name that case.
    pub fn refused_publications(&self) -> u64 {
        self.arrivals.refused_outbound.load(Ordering::Relaxed) + (self.pool_unsent)()
    }

    /// The share's group prefix: the host's minted one, or the one an invite
    /// named. Every topic this session publishes under starts with it.
    pub fn group_prefix(&self) -> &str {
        &self.prefix
    }

    /// Why this node is not in its share yet, when it is not: the group's key
    /// distributor has not answered. An application shows the waiting state
    /// from this, and publishes nothing until it is `None` — a publication
    /// attempted meanwhile is refused, never sent in the clear. `None` means
    /// the share's seven topics are subscribed under a key this node holds.
    pub fn waiting(&self) -> Option<Reason> {
        self.waiting.lock().ok().and_then(|waiting| *waiting)
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
        let host = cfg.hosting;
        let prefix = match (host, cfg.share.prefix.is_empty()) {
            (true, true) => mint_share_prefix(&cfg.realm_name, identity.node_id())?,
            (_, false) => cfg.share.prefix.clone(),
            (false, true) => {
                return Err("a joiner is given its share's group prefix by the invite; without one there is nothing to join".into());
            }
        };
        // Every share here is sealed, and a sealed share's distributor is
        // pinned (threat model T5): macula-rust's member side auto-pins the
        // first answer when no pin is given, so a share that names none is
        // refused here rather than joined on whoever answers first. The one
        // exception is a host, which is its own distributor and pins itself
        // further down.
        if !host && cfg.share.distributor.is_none() {
            return Err(format!(
                "{prefix}: a sealed share's distributor must be pinned to a node id (the invite names it); an unpinned share is refused rather than joined on the first answer"
            ));
        }
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
        let waiting = Arc::new(Mutex::new(None));
        let waiting_in_thread = waiting.clone();
        std::thread::Builder::new()
            .name("macula-craft-collab".into())
            .spawn(move || {
                run_on_new_runtime(
                    cfg,
                    host,
                    key,
                    identity,
                    group,
                    in_tx,
                    ready_tx,
                    dropped_in_thread,
                    arrivals_in_thread,
                    membership_in_thread,
                    waiting_in_thread,
                );
            })
            .map_err(|e| format!("thread: {e}"))?;
        match ready_rx.recv() {
            Ok(Ok(Ready { out, pool_unsent })) => {
                Ok(MeshTransport { author, prefix, out, incoming: in_rx, dropped_unverified: dropped, arrivals, membership, waiting, pool_unsent })
            }
            Ok(Err(e)) => Err(e),
            Err(e) => Err(format!("the mesh thread ended before it was ready: {e}")),
        }
    }
}

/// The share prefix a host mints: `<realm>/~<host>/craft/<share>`, the share
/// id random and per session. Random and not derived from the document, so a
/// document's permanent id never appears in a topic the realm can see, and
/// per session, so yesterday's topics are gone when sharing starts again.
pub fn mint_share_prefix(realm_name: &str, host_hex: &str) -> Result<String, String> {
    let mut id = [0u8; 16];
    getrandom::getrandom(&mut id).map_err(|e| format!("no randomness for a share id: {e}"))?;
    let share: String = id.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("{realm_name}/~{host_hex}/craft/{share}"))
}

/// How long the host's own credential to pull its share's key lives. It
/// bounds nothing but this session — the host is the org, so there is no
/// grant for it to outlive — and it is minted again at every connect.
const HOST_CREDENTIAL_MS: u64 = 365 * 24 * 60 * 60 * 1_000;

/// The group this node subscribes and publishes under: the one it was given,
/// or, as a host, the one it minted a prefix for — its distributor served and
/// its own credential pulled from it. The serving comes back so the share
/// keeps it for as long as it runs.
async fn joined_group(
    pool: &Pool,
    cfg: &MeshConfig,
    key: &Arc<NodeKey>,
    group: &Group,
    host: bool,
) -> Result<(Group, Option<macula_rust::pool::Served>), String> {
    match host {
        true => serve_share(pool, cfg, key, group).await.map(|(group, served)| (group, Some(served))),
        false => Ok((group.clone(), None)),
    }
}

/// The host's half of a share: serve its key distributor in this node's own
/// namespace, then take the host's own credential, so its join below is a
/// pull like any other. Returns the group to subscribe and publish under,
/// and the serving, which must be kept for as long as the share lasts.
async fn serve_share(pool: &Pool, cfg: &MeshConfig, key: &Arc<NodeKey>, group: &Group) -> Result<(Group, macula_rust::pool::Served), String> {
    let (Some(membership), Some(removed)) = (cfg.membership.clone(), cfg.removed.clone()) else {
        return Err(
            "this host has no admission record for its share, so it can admit nobody to the document's key: refusing to share rather than fail later"
                .into(),
        );
    };
    let served = serve_distributor(pool, cfg, key, group, membership, removed).await?;
    let self_id = key.node_id().map_err(|e| format!("the identity's node id: {e:?}"))?;
    let org = org_of(&group.prefix).map_err(|e| format!("the share's prefix: {e}"))?;
    let now_ms = craft_collab::now_ms();
    let ucan = crate::issuer::group_ucan(key, &cfg.realm_name, org, &self_id, HOST_CREDENTIAL_MS, now_ms)?;
    Ok((Group { prefix: group.prefix.clone(), ucan: ucan.into_bytes(), distributor: Some(self_id) }, served))
}

/// Serves `<org>/group_keys_v1` for the share, sealed and grant-gated, with
/// this host's own answers for who may pull.
async fn serve_distributor(
    pool: &Pool,
    cfg: &MeshConfig,
    key: &Arc<NodeKey>,
    group: &Group,
    membership: MembershipCheck,
    removed: RemovedCheck,
) -> Result<macula_rust::pool::Served, String> {
    let org = org_of(&group.prefix).map_err(|e| format!("the share's prefix: {e}"))?;
    let mut options = DistributorOptions::new(org, Policy::Required, membership);
    options.removed = removed;
    let distributor = Distributor::new(options).map_err(|e| format!("the key distributor: {e}"))?;
    let org_key_id = key_id_of(&key.public_key(), key.profile());
    pool.serve(distributor.offer(cfg.realm_id, org_key_id)).await.map_err(|e| format!("the share's key distributor was not served: {e:?}"))
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
    /// Whether this node minted the share's prefix, which is what makes it
    /// the share's key distributor.
    host: bool,
    key: Arc<NodeKey>,
    identity: Identity,
    group: Group,
    ready: std::sync::mpsc::Sender<Result<Ready, String>>,
    dropped: Arc<AtomicU64>,
    arrivals: Arrivals,
    membership: Arc<Mutex<Option<String>>>,
    waiting: Arc<Mutex<Option<Reason>>>,
}

/// Builds the mesh thread's runtime and runs the transport loop on it. A
/// runtime that cannot be built is reported where a failed connect is.
#[allow(clippy::too_many_arguments)]
fn run_on_new_runtime(
    cfg: MeshConfig,
    host: bool,
    key: Arc<NodeKey>,
    identity: Identity,
    group: Group,
    in_tx: Sender<Message>,
    ready: std::sync::mpsc::Sender<Result<Ready, String>>,
    dropped: Arc<AtomicU64>,
    arrivals: Arrivals,
    membership: Arc<Mutex<Option<String>>>,
    waiting: Arc<Mutex<Option<Reason>>>,
) {
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = ready.send(Err(format!("runtime: {e}")));
            return;
        }
    };
    let thread = MeshThread { cfg, host, key, identity, group, ready, dropped, arrivals, membership, waiting };
    rt.block_on(run(thread, in_tx));
}

/// Runs until the transport is dropped: then the outbound channel closes,
/// the loop ends and the pool closes.
async fn run(thread: MeshThread, in_tx: Sender<Message>) {
    let MeshThread { cfg, host, key, identity, group, ready, dropped, arrivals, membership, waiting } = thread;
    let mut opts = Opts::new(key.clone());
    // Pubsub needs no realm trust: it is only consulted when a call resolves
    // an advertisement. An empty key means "trust nothing in this realm".
    if !cfg.realm_key.is_empty() {
        opts.realm_trust.insert(cfg.realm_id, cfg.realm_key.clone());
    }
    // This node opens sealed requests (a key pull is one) and, as a host,
    // advertises a sealed procedure: both need the KEM key in the
    // advertisement.
    opts.kem_advertise = true;
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

    // A host serves its share's key distributor before it pulls anything:
    // its own join below is a pull from itself, and a share whose key cannot
    // be had fails here rather than falling back to the clear.
    let (group, _served) = match joined_group(&pool, &cfg, &key, &group, host).await {
        Ok(joined) => joined,
        Err(e) => {
            let _ = ready.send(Err(e));
            return;
        }
    };

    let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel::<Outbound>();
    // Subscribing under the group joins it first, so the key is pulled before
    // this session can publish anything: a joiner has its key before it
    // knocks. A group whose key cannot be had fails closed — and while the
    // share's distributor is simply not answering yet, the transport waits
    // for it instead of taking the session down (threat model T11).
    let started = start_share(&pool, &cfg, &group, &in_tx, &dropped, &arrivals, &waiting).await;
    if let Err(e) = started {
        let _ = ready.send(Err(e));
        return;
    }
    // The transport holds the only sender; when it drops, the channel ends.
    // The pool's own count travels with it: what the pool accepted and could
    // not deliver is part of what an app is told (macula-craft-collab#38).
    let pool_unsent: PoolUnsent = {
        let pool = pool.clone();
        Arc::new(move || pool.unsent_publications())
    };
    let _ = ready.send(Ok(Ready { out: out_tx, pool_unsent }));

    let realm = cfg.realm_id;
    while let Some(out) = out_rx.recv().await {
        match out {
            Outbound::DeviceJoin { realm_name, reply } => {
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
                // Through the renewal path, so a person's stored fields stay.
                let _ = reply.send(realm::renew_membership(&pool, &identity, &realm_name, now).await);
            }
            Outbound::Publish(topic, json) => publish_sealed(&pool, realm, &group, topic, json, &waiting, &arrivals).await,
        }
    }
    pool.close().await;
}

/// Publishes one message sealed under the share's group.
///
/// There is no clear arm on purpose: a publication that is not under the
/// group is refused rather than sent in the open. A publication that fails is
/// counted (`refused_publications`) and not sent: the message never left, and
/// nothing goes out in the clear instead. A reason that is about the share
/// rather than this message — the key is out of reach, this node was removed —
/// also sets `waiting()`; a reason that is about the one message leaves the
/// share usable and the counter is the signal. The seam does not see the
/// failure (`send` is fire-and-forget), so the count is what an application
/// shows.
async fn publish_sealed(
    pool: &Pool,
    realm: [u8; 32],
    group: &Group,
    topic: String,
    json: String,
    waiting: &Arc<Mutex<Option<Reason>>>,
    arrivals: &Arrivals,
) {
    let payload = Value::Map(vec![(Value::text("json"), Value::text(json))]);
    match pool.publish_group(&realm, &topic, group, payload).await {
        Ok(()) => note_sharing(waiting, None),
        Err(e) => {
            // The message never left: counted, and never sent in the clear.
            arrivals.refused_outbound.fetch_add(1, Ordering::Relaxed);
            eprintln!("craft-collab: {topic} was not published: {e:?}");
            if let Some(reason) = waiting_reason(&e) {
                note_sharing(waiting, Some(reason));
            }
        }
    }
}

/// Why a publication or an event says this node is not in its share, when it
/// does: a key it could not pull (`no_distributor`), or a group it has been
/// removed from. Any other reason is about one message, not the share.
pub(crate) fn waiting_reason(error: &macula_rust::group::GroupError) -> Option<Reason> {
    share_level(error.reason()?)
}

/// A reason that is about the share rather than one message: the key cannot
/// be had, or this node is no longer a holder. Everything else — an event
/// sealed under an epoch too old to open, a tag that does not verify — is
/// about the one event that carried it.
fn share_level(reason: Reason) -> Option<Reason> {
    matches!(reason, Reason::NoDistributor | Reason::NotAMember | Reason::MembershipUnknown).then_some(reason)
}

/// Records the share's state: `Some(reason)` while it cannot be used, `None`
/// once it works again.
fn note_sharing(waiting: &Arc<Mutex<Option<Reason>>>, reason: Option<Reason>) {
    *waiting.lock().unwrap_or_else(|p| p.into_inner()) = reason;
}

/// The topic a message's kind travels on, under the share's prefix.
fn topic_of(prefix: &str, name: &str) -> String {
    format!("{prefix}/{name}")
}

/// How long a share waits for its key distributor before asking it again.
const DISTRIBUTOR_RETRY: std::time::Duration = std::time::Duration::from_secs(10);

/// Puts the share on the wire: subscribed under its group, or waiting for the
/// distributor that holds the key. `Err` is the share's own refusal, which
/// fails the connect rather than waiting for ever.
#[allow(clippy::too_many_arguments)]
async fn start_share(
    pool: &Pool,
    cfg: &MeshConfig,
    group: &Group,
    in_tx: &Sender<Message>,
    dropped: &Arc<AtomicU64>,
    arrivals: &Arrivals,
    waiting: &Arc<Mutex<Option<Reason>>>,
) -> Result<(), String> {
    match subscribe_all(pool, cfg, group).await {
        Ok(subs) => {
            *waiting.lock().unwrap_or_else(|p| p.into_inner()) = None;
            pump_all(subs, in_tx, dropped, arrivals, waiting);
            Ok(())
        }
        // Two reasons are the share waiting for an answer rather than a
        // refusal of it: no distributor yet, and a distributor that cannot say
        // who is a member. Both may change without this node doing anything,
        // so both are retried instead of ending the share.
        Err(e) if e.is(Reason::NoDistributor) || e.is(Reason::MembershipUnknown) => {
            let reason = e.reason().unwrap_or(Reason::NoDistributor);
            *waiting.lock().unwrap_or_else(|p| p.into_inner()) = Some(reason);
            tokio::spawn(wait_for_distributor(
                pool.clone(),
                cfg.clone(),
                group.clone(),
                in_tx.clone(),
                dropped.clone(),
                arrivals.clone(),
                waiting.clone(),
            ));
            Ok(())
        }
        Err(e) => Err(format!("{e}")),
    }
}

/// Subscribes this node to every topic a share carries, all or none: each
/// subscription joins the share's group first, which is the key pull, so a
/// refusal is the group's answer and not one topic's.
async fn subscribe_all(pool: &Pool, cfg: &MeshConfig, group: &Group) -> Result<Vec<Subscription>, macula_rust::group::GroupError> {
    let mut subs = Vec::with_capacity(NAMES.len());
    for name in NAMES {
        let topic = topic_of(&group.prefix, name);
        subs.push(pool.subscribe_group(&cfg.realm_id, &topic, group).await?);
    }
    Ok(subs)
}

/// Hands each subscription to the transport, on a task of its own.
fn pump_all(subs: Vec<Subscription>, in_tx: &Sender<Message>, dropped: &Arc<AtomicU64>, arrivals: &Arrivals, waiting: &Arc<Mutex<Option<Reason>>>) {
    for sub in subs {
        tokio::spawn(pump_events(sub, in_tx.clone(), dropped.clone(), arrivals.clone(), waiting.clone()));
    }
}

/// Waits for the share's key distributor, then subscribes: the visible,
/// fail-closed waiting state of threat model T11. Until it answers, nothing
/// is subscribed and every publication is refused; the reason is published
/// through `waiting` so an application can say what it is waiting for.
#[allow(clippy::too_many_arguments)]
async fn wait_for_distributor(
    pool: Pool,
    cfg: MeshConfig,
    group: Group,
    in_tx: Sender<Message>,
    dropped: Arc<AtomicU64>,
    arrivals: Arrivals,
    waiting: Arc<Mutex<Option<Reason>>>,
) {
    loop {
        tokio::time::sleep(DISTRIBUTOR_RETRY).await;
        match subscribe_all(&pool, &cfg, &group).await {
            Ok(subs) => {
                note_sharing(&waiting, None);
                pump_all(subs, &in_tx, &dropped, &arrivals, &waiting);
                return;
            }
            // Two reasons go on waiting: no distributor yet, and one that
            // cannot read this node's membership. Anything else is the group's
            // answer, and a share waiting on that would wait for ever.
            Err(e) if e.is(Reason::NoDistributor) || e.is(Reason::MembershipUnknown) => {}
            Err(e) => {
                let reason = e.reason().unwrap_or(Reason::NoDistributor);
                *waiting.lock().unwrap_or_else(|p| p.into_inner()) = Some(reason);
                eprintln!("craft-collab: the share cannot be joined: {e}");
                return;
            }
        }
    }
}

/// Feeds a subscription's events to the transport until the transport drops
/// its receiving end or the subscription ends.
async fn pump_events(mut sub: Subscription, tx: Sender<Message>, dropped: Arc<AtomicU64>, arrivals: Arrivals, waiting: Arc<Mutex<Option<Reason>>>) {
    while let Some(event) = sub.recv().await {
        if !deliver_event(&event, &tx, &dropped, &arrivals, &waiting) {
            break;
        }
    }
}

/// Hands one delivered event to the transport as a message, or counts it as
/// one of the ways an event can be refused; false when the receiving end has
/// closed.
fn deliver_event(event: &Event, tx: &Sender<Message>, dropped: &Arc<AtomicU64>, arrivals: &Arrivals, waiting: &Arc<Mutex<Option<Reason>>>) -> bool {
    // A sealed event that did not open arrives with no payload and the reason
    // it failed. It is counted and never applied: the alternative is a
    // ciphertext treated as a payload.
    if let Some(reason) = event.unopened {
        arrivals.unopened.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut last) = arrivals.last_unopened.lock() {
            *last = Some(reason);
        }
        // An event this node could not open because the key is out of reach
        // is the same waiting state a refused publication shows.
        if let Some(state) = share_level(reason) {
            note_sharing(waiting, Some(state));
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
        // Opened, and then nothing this crate can carry: counted, not
        // swallowed.
        arrivals.unusable.fetch_add(1, Ordering::Relaxed);
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
        // Asked to send and could not, for either reason: serialisation, or
        // the mesh thread gone (its channel is closed once it has ended).
        // The seam ignores this answer, so counting it here is the only way
        // the app is told (macula-craft-collab#39).
        let json = match serde_json::to_string(&msg) {
            Ok(json) => json,
            Err(e) => {
                self.arrivals.refused_outbound.fetch_add(1, Ordering::Relaxed);
                return Err(e.to_string());
            }
        };
        self.out.send(Outbound::Publish(topic, json)).map_err(|_| {
            self.arrivals.refused_outbound.fetch_add(1, Ordering::Relaxed);
            "the mesh link has ended".to_string()
        })
    }

    fn poll(&mut self) -> Vec<Message> {
        self.incoming.try_iter().collect()
    }

    fn membership(&self) -> Option<String> {
        self.membership.lock().ok()?.clone()
    }

    fn refused_publications(&self) -> u64 {
        // The same number an app holding the transport reads directly: two
        // sources, one answer.
        MeshTransport::refused_publications(self)
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

/// Hex digits in pairs, as bytes.
pub(crate) fn hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return Err("hex digits expected, in pairs".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| s.get(i..i + 2).ok_or("hex").and_then(|p| u8::from_str_radix(p, 16).map_err(|_| "hex")).map_err(String::from))
        .collect()
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

    /// A transport whose outbound channel is `out`, with the pool's count
    /// answered by `pool_unsent`: everything the two tests below need, and
    /// nothing that dials a station.
    fn transport_with(out: UnboundedSender<Outbound>, pool_unsent: PoolUnsent) -> MeshTransport {
        let (_in_tx, incoming) = arriving();
        MeshTransport {
            author: "aabbcc".into(),
            prefix: "io.macula/~aabbcc/craft/9f9f".into(),
            out,
            incoming,
            dropped_unverified: Arc::new(AtomicU64::new(0)),
            arrivals: Arrivals::default(),
            membership: Arc::new(Mutex::new(None)),
            waiting: Arc::new(Mutex::new(None)),
            pool_unsent,
        }
    }

    fn a_message(author: &str) -> Message {
        Message { doc: "demo".into(), author: author.into(), epoch: 1, seq: 1, sent_at_ms: 0, kind: Kind::CursorMoved { position: None, name: None } }
    }

    /// #39, first source: what the pool accepted and could not deliver
    /// because the link ended first is part of the number the app reads
    /// (macula-craft-collab#38). The pool's own counter is macula-rust's to
    /// test; what this asserts is that this crate adds it, beside its own.
    #[test]
    fn what_the_pool_could_not_deliver_is_counted_beside_what_the_mesh_refused() {
        let (out, out_rx) = tokio::sync::mpsc::unbounded_channel();
        let transport = transport_with(out, Arc::new(|| 3));
        transport.arrivals.refused_outbound.fetch_add(2, Ordering::Relaxed);
        assert_eq!(transport.refused_publications(), 5, "the app's number is the pool's count plus the mesh's refusals");
        drop(out_rx);
    }

    /// #39, second source: an edit the transport is asked to send after the
    /// mesh side has ended cannot be sent, and is counted rather than lost
    /// without a word. The seam ignores `send`'s answer, so this is the only
    /// place it can be counted.
    #[test]
    fn a_send_after_the_mesh_side_ended_is_counted() {
        let (out, out_rx) = tokio::sync::mpsc::unbounded_channel();
        // The mesh thread has ended: its receiving half is gone, exactly as
        // when the transport loop returns and drops it.
        drop(out_rx);
        let mut transport = transport_with(out, Arc::new(|| 0));
        assert_eq!(transport.refused_publications(), 0, "nothing has been asked of it yet");
        transport.send(a_message("aabbcc")).expect_err("the mesh side is gone, so the edit cannot be sent");
        assert_eq!(transport.refused_publications(), 1, "an edit the app asked to send and could not is counted, not swallowed");
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
        let first = mint_share_prefix("io.macula", &host).expect("a share id");
        let second = mint_share_prefix("io.macula", &host).expect("a share id");
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
        let waiting = Arc::new(Mutex::new(None));
        let event = event(Payload::Clear(Value::Null), Some([1u8; 8]), Some(Reason::UnknownEpoch));
        assert!(deliver_event(&event, &tx, &dropped, &arrivals, &waiting), "the pump carries on");
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
        let waiting = Arc::new(Mutex::new(None));
        let event = event(publishable(&msg_json("0303030303")), None, None);
        assert!(deliver_event(&event, &tx, &dropped, &arrivals, &waiting));
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
        let waiting = Arc::new(Mutex::new(None));
        let forged = msg_json("aabbcc");
        let event = event(publishable(&forged), Some([2u8; 8]), None);
        assert!(deliver_event(&event, &tx, &dropped, &arrivals, &waiting));
        assert!(rx.try_recv().is_err(), "a forged author is not delivered");
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        assert_eq!(arrivals.clear_refused.load(Ordering::Relaxed), 0, "an opened event is not a clear one");
    }

    /// An event that opened and carried nothing this crate can use is counted,
    /// not swallowed: it is the one inbound drop that used to leave no mark.
    #[test]
    fn an_opened_event_without_a_message_is_counted() {
        let (tx, rx) = arriving();
        let dropped = Arc::new(AtomicU64::new(0));
        let arrivals = Arrivals::default();
        let waiting = Arc::new(Mutex::new(None));
        let payload = Payload::Clear(Value::Map(vec![(Value::text("note"), Value::text("not a message"))]));
        let event = event(payload, Some([2u8; 8]), None);
        assert!(deliver_event(&event, &tx, &dropped, &arrivals, &waiting));
        assert!(rx.try_recv().is_err(), "nothing unusable is handed to the seam");
        assert_eq!(arrivals.unusable.load(Ordering::Relaxed), 1, "and it is counted");
        assert_eq!(dropped.load(Ordering::Relaxed), 0, "not a forged author");
        assert_eq!(arrivals.clear_refused.load(Ordering::Relaxed), 0, "not a clear event either");
    }
}
