//! How many app bytes one sealed publication can carry
//! (macula-apps/martha-board#2, design r=4 and r=5).
//!
//! The link refuses a frame whose encoding is over [`MAX_FRAME_BYTES`], and
//! the seam never hears of it: the message is counted as refused and nothing
//! else happens. An app that must not lose a large message (a board's
//! welcome) asks first how large it may be, and refuses the change that
//! would go over before it applies it locally.
//!
//! The answer is measured through the path a publication takes: the seam
//! message as `send` serialises it, the `{"json": …}` wrapping
//! `publish_sealed` gives it, `group::seal_event`, `frame::sign_publish` and
//! `cbor::encode`. No margin and no size is written down here, so the
//! answer moves with the protocol.
//!
//! A subscriber never reads the PUBLISH the link sends: it reads an EVENT or
//! a GOSSIP around the same signed publication, under the same cap, and a
//! station may add a `frame_id` and a `sent_at_ms` to either. So the answer
//! is the largest that fits in the widest of the three (design r=5, R1), with
//! each extra field as wide as the subscriber's own check,
//! `frame::verify_publication`, accepts.

use craft_collab::{Kind, Message};
use macula_rust::cbor::{self, Value};
use macula_rust::frame::{self, MAX_FRAME_BYTES, Payload, PublicationSpec};
use macula_rust::group::{self, Epoch, Fields, ID_SIZE, KEY_SIZE};
use macula_rust::node_key::{NodeKey, Purpose};
use macula_rust::profile::Profile;

use crate::{MeshTransport, name_for, topic_of, wire_json, wire_payload};

/// The publication seq and time the worst case is measured with: the
/// smallest integer CBOR writes in its widest form (an eight-byte argument).
/// `u64::MAX` would be wider still, but `frame::sign_publish` refuses a seq
/// or time of 2^53 or more, and every integer from here up to that cap
/// encodes to the same length.
const WIDEST_PROTOCOL_INT: u64 = u32::MAX as u64 + 1;

/// The wire 1.0 names of the frames a subscriber reads and of their extra
/// fields. They are private in macula-rust 0.15, so they are written here
/// once. No size comes from them, and every measurement has
/// `frame::verify_publication` accept the frames built with them, so a
/// renamed field is an error, never a wrong ceiling.
const FRAME_TYPE: &str = "frame_type";
const EVENT: &str = "event";
const GOSSIP: &str = "plumtree_gossip";
const DELIVERED_VIA: &str = "delivered_via";
const ROUND: &str = "round";
const FRAME_ID: &str = "frame_id";
const SENT_AT_MS: &str = "sent_at_ms";

impl MeshTransport {
    /// The most app bytes `envelope` can carry in one publication on this
    /// share: `envelope` is the message the app will send, with its app
    /// bytes left empty (`Command.params`, `Snapshot.data` or
    /// `TextEdit.update`), and `profile` is the publishing identity's.
    ///
    /// It is the worst case for that envelope: every app byte `255`, the
    /// message's own epoch, seq and time at `u64::MAX`, the publication's seq
    /// and time in their widest encoding, and the widest frame a subscriber
    /// reads it in. So an app that keeps its bytes at or under the answer is
    /// never refused by the frame cap, sending or receiving. It is found by
    /// bisection over real sealed frames, so an app computes it once per
    /// share and message kind, and keeps it.
    ///
    /// The answer holds for an envelope whose other fields (doc, author, id,
    /// anchor, para, props, a snapshot's `crdt`) are no longer than the ones
    /// measured. An app whose envelope grows measures again.
    ///
    /// An envelope of another kind has no app bytes and is refused, as is
    /// one that is over the cap with no app bytes at all.
    pub fn largest_payload_that_fits(prefix: &str, profile: Profile, envelope: &Message) -> Result<usize, String> {
        let mut probe = Probe::new(prefix, profile, envelope)?;
        probe.widest = Widest::measure(&probe, profile)?;
        if !probe.fits(0)? {
            return Err(format!("the envelope alone is over the {MAX_FRAME_BYTES}-byte frame cap"));
        }
        // Each app byte adds at least its JSON width to the frame (the seal
        // and the CBOR only add to it), so this many never fit.
        let over_bound = MAX_FRAME_BYTES / json_width_of_a_byte()? + 2;
        largest_accepted(0, over_bound, |n| probe.fits(n))
    }
}

/// The largest `n` in `fits..over` that `accepted` takes, by bisection:
/// `accepted(fits)` holds, `accepted(over)` does not, and `accepted` holds
/// for every `n` up to some point and for none past it.
fn largest_accepted(mut fits: usize, mut over: usize, mut accepted: impl FnMut(usize) -> Result<bool, String>) -> Result<usize, String> {
    while over - fits > 1 {
        let mid = fits + (over - fits) / 2;
        let taken = accepted(mid)?;
        fits = if taken { mid } else { fits };
        over = if taken { over } else { mid };
    }
    Ok(fits)
}

/// What one more `255` adds to a byte array as serde writes it (the digits
/// and the comma), measured rather than written down.
fn json_width_of_a_byte() -> Result<usize, String> {
    let width = |n: usize| serde_json::to_string(&vec![u8::MAX; n]).map(|s| s.len()).map_err(|e| e.to_string());
    Ok(width(2)? - width(1)?)
}

/// One envelope, measured: its topic, its worst-case fields, and a
/// throwaway key and epoch to seal and sign it with.
struct Probe {
    topic: String,
    envelope: Message,
    key: NodeKey,
    epoch: Epoch,
    widest: Widest,
}

impl Probe {
    fn new(prefix: &str, profile: Profile, envelope: &Message) -> Result<Probe, String> {
        let mut envelope = envelope.clone();
        if app_bytes(&mut envelope.kind).is_none() {
            return Err("this kind of message carries no app bytes".into());
        }
        envelope.epoch = u64::MAX;
        envelope.seq = u64::MAX;
        envelope.sent_at_ms = u64::MAX;
        let topic = topic_of(prefix, name_for(&envelope.kind));
        let key = NodeKey::generate(Purpose::Identity, profile).map_err(|e| format!("a throwaway key: {e:?}"))?;
        let epoch = Epoch::new([0; ID_SIZE], [0; KEY_SIZE], 0, i64::MAX, i64::MAX);
        Ok(Probe { topic, envelope, key, epoch, widest: Widest::default() })
    }

    /// Whether the envelope with `n` app bytes, all `255`, fits the PUBLISH
    /// and the widest EVENT and GOSSIP a subscriber reads it in.
    fn fits(&self, n: usize) -> Result<bool, String> {
        let Some(publish) = self.signed(n)? else { return Ok(false) };
        let lens = [self.widest.event(&publish), self.widest.gossip(&publish), publish]
            .iter()
            .map(|frame| cbor::encode(frame).map(|bytes| bytes.len()).map_err(|e| format!("the frame: {e:?}")))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(lens.iter().all(|&len| len <= MAX_FRAME_BYTES))
    }

    /// The PUBLISH of the envelope with `n` app bytes, all `255`, sealed and
    /// signed; `None` when its payload alone is over the cap.
    fn signed(&self, n: usize) -> Result<Option<Value>, String> {
        let mut msg = self.envelope.clone();
        if let Some(bytes) = app_bytes(&mut msg.kind) {
            *bytes = vec![u8::MAX; n];
        }
        let payload = wire_payload(wire_json(&msg)?);
        // A payload over the cap on its own is refused by the seal; that is
        // "does not fit", not a failure to measure.
        if cbor::encode(&payload).map_err(|e| format!("the payload: {e:?}"))?.len() > MAX_FRAME_BYTES {
            return Ok(None);
        }
        let fields = Fields {
            realm: [0; 32],
            topic: self.topic.clone(),
            publisher: self.key.key_id(),
            seq: WIDEST_PROTOCOL_INT,
            published_at: WIDEST_PROTOCOL_INT,
        };
        let sealed = group::seal_event(&self.epoch, &fields, &payload).map_err(|e| format!("the seal: {e:?}"))?;
        let spec = PublicationSpec {
            realm: fields.realm,
            topic: fields.topic,
            seq: fields.seq,
            published_at: fields.published_at,
            payload: Payload::Sealed(sealed),
            ttl_ms: None,
        };
        frame::sign_publish(&spec, &self.key).map(Some).map_err(|e| format!("the signature: {e:?}"))
    }
}

/// How wide a subscriber's check lets a delivered frame's extra fields be,
/// measured through that check (`frame::verify_publication`) rather than
/// written down: its limits are private in macula-rust 0.15.
#[derive(Default)]
struct Widest {
    delivered_via: usize,
    frame_id: usize,
}

impl Widest {
    /// Measures the widths on the envelope's own PUBLISH with no app bytes,
    /// then has the check accept the widest EVENT and GOSSIP built with them.
    fn measure(probe: &Probe, profile: Profile) -> Result<Widest, String> {
        let small = probe.signed(0)?.ok_or("the envelope alone is over the frame cap")?;
        let small_len = cbor::encode(&small).map_err(|e| format!("the frame: {e:?}"))?.len();
        let accepts = |frame: &Value| frame::verify_publication(frame, profile, now_of_the_probe()).is_ok();
        // A frame_id has one accepted length; none longer than the frame it
        // rides on is looked for.
        let frame_id = (1..=small_len)
            .find(|&len| accepts(&delivered(&small, GOSSIP, vec![round(), (Value::text(FRAME_ID), Value::Bytes(vec![0; len]))])))
            .ok_or("macula-rust accepts no frame_id this crate can measure")?;
        let via = |len: usize| delivered(&small, EVENT, vec![(Value::text(DELIVERED_VIA), Value::text("x".repeat(len)))]);
        if !accepts(&via(1)) {
            return Err("macula-rust no longer accepts the delivered frame this crate measures".into());
        }
        // The longest delivered_via accepted: doubled until refused, then
        // bisected, never past the cap.
        let mut over = 2;
        while over <= MAX_FRAME_BYTES && accepts(&via(over)) {
            over *= 2;
        }
        let longest = largest_accepted(over / 2, over, |len| Ok(accepts(&via(len))))?;
        let widest = Widest { delivered_via: longest, frame_id };
        if !accepts(&widest.event(&small)) || !accepts(&widest.gossip(&small)) {
            return Err("macula-rust no longer accepts the delivered frame this crate measures".into());
        }
        Ok(widest)
    }

    /// The widest EVENT around `publish`.
    fn event(&self, publish: &Value) -> Value {
        let mut extra = vec![(Value::text(DELIVERED_VIA), Value::text("x".repeat(self.delivered_via)))];
        extra.extend(self.routing());
        delivered(publish, EVENT, extra)
    }

    /// The widest GOSSIP around `publish`.
    fn gossip(&self, publish: &Value) -> Value {
        let mut extra = vec![round()];
        extra.extend(self.routing());
        delivered(publish, GOSSIP, extra)
    }

    /// The fields a station may add to either.
    fn routing(&self) -> [(Value, Value); 2] {
        [(Value::text(FRAME_ID), Value::Bytes(vec![0; self.frame_id])), (Value::text(SENT_AT_MS), widest_int())]
    }
}

/// `publish`'s map as a frame of `frame_type`, with `extra` added.
fn delivered(publish: &Value, frame_type: &str, extra: Vec<(Value, Value)>) -> Value {
    let Value::Map(entries) = publish else { return publish.clone() };
    let mut out: Vec<(Value, Value)> = entries.iter().filter(|(k, _)| k != &Value::text(FRAME_TYPE)).cloned().collect();
    out.push((Value::text(FRAME_TYPE), Value::text(frame_type)));
    out.extend(extra);
    Value::Map(out)
}

fn round() -> (Value, Value) {
    (Value::text(ROUND), widest_int())
}

fn widest_int() -> Value {
    Value::Int(i128::from(WIDEST_PROTOCOL_INT))
}

/// The clock the check runs on: the probe's own publication time, so a
/// frame is judged on its shape, never refused as expired.
fn now_of_the_probe() -> i64 {
    i64::try_from(WIDEST_PROTOCOL_INT).unwrap_or(i64::MAX)
}

/// The field of `kind` that holds the app's own bytes, when it has one.
fn app_bytes(kind: &mut Kind) -> Option<&mut Vec<u8>> {
    match kind {
        Kind::Command { params, .. } => Some(params),
        Kind::Snapshot { data, .. } => Some(data),
        Kind::TextEdit { update, .. } => Some(update),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use craft_collab::Transport;

    use super::*;
    use crate::Outbound;
    use crate::tests::transport_with;

    /// The widest frame a publication of `msg` is read in: what `send` really
    /// hands the mesh thread, sealed and signed the way `Pool::publish_group`
    /// does it under a key of `profile`, then the PUBLISH, and the EVENT and
    /// GOSSIP a station delivers it in at their widest. Built here, apart from
    /// the ceiling's own measuring, and each one accepted by the subscriber's
    /// check.
    fn widest_received_len(msg: Message, profile: Profile) -> usize {
        let (out, mut out_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut transport = transport_with(out, Arc::new(|| 0));
        transport.send(msg).expect("sent");
        let Ok(Outbound::Publish(topic, json)) = out_rx.try_recv() else { panic!("send published nothing") };
        let key = NodeKey::generate(Purpose::Identity, profile).expect("key");
        let epoch = Epoch::new([7; ID_SIZE], [9; KEY_SIZE], 1, i64::MAX, i64::MAX);
        // The largest seq and time the frame accepts: a different value from
        // the one the ceiling measures with, in the same widest encoding.
        let widest = (1u64 << 53) - 1;
        let realm = [3; 32];
        let fields = Fields { realm, topic: topic.clone(), publisher: key.key_id(), seq: widest, published_at: widest };
        let sealed = group::seal_event(&epoch, &fields, &wire_payload(json)).expect("sealed");
        let spec = PublicationSpec { realm, topic, seq: widest, published_at: widest, payload: Payload::Sealed(sealed), ttl_ms: None };
        let publish = frame::sign_publish(&spec, &key).expect("signed");
        let now = i64::try_from(widest).expect("fits");
        let frames =
            [publish.clone(), widest_event(&publish, Value::Int(i128::from(widest))), widest_gossip(&publish, Value::Int(i128::from(widest)))];
        for f in &frames {
            frame::verify_publication(f, profile, now).expect("a subscriber reads it");
        }
        frames.iter().map(|f| cbor::encode(f).expect("encoded").len()).max().expect("three frames")
    }

    /// The limits of macula-rust 0.15's received-frame check, as its wire 1.0
    /// table states them (`frame.rs:91`, `:403`), written down here so the
    /// test does not share the ceiling's measuring;
    /// [`these_are_the_widest_a_subscriber_accepts`] proves them on the
    /// crate.
    const DELIVERED_VIA_BYTES: usize = 64;
    const FRAME_ID_BYTES: usize = 16;

    fn with(publish: &Value, frame_type: &str, extra: Vec<(&str, Value)>) -> Value {
        let Value::Map(entries) = publish else { panic!("a frame is a map") };
        let mut out: Vec<(Value, Value)> = entries.iter().filter(|(k, _)| k != &Value::text("frame_type")).cloned().collect();
        out.push((Value::text("frame_type"), Value::text(frame_type)));
        out.extend(extra.into_iter().map(|(k, v)| (Value::text(k), v)));
        Value::Map(out)
    }

    fn widest_event(publish: &Value, int: Value) -> Value {
        with(
            publish,
            "event",
            vec![
                ("delivered_via", Value::text("d".repeat(DELIVERED_VIA_BYTES))),
                ("frame_id", Value::Bytes(vec![1; FRAME_ID_BYTES])),
                ("sent_at_ms", int),
            ],
        )
    }

    fn widest_gossip(publish: &Value, int: Value) -> Value {
        with(publish, "plumtree_gossip", vec![("round", int.clone()), ("frame_id", Value::Bytes(vec![1; FRAME_ID_BYTES])), ("sent_at_ms", int)])
    }

    /// The test's own widths are the widest the check accepts: one byte more
    /// of `delivered_via` or `frame_id` is refused.
    #[test]
    fn these_are_the_widest_a_subscriber_accepts() {
        let key = NodeKey::generate(Purpose::Identity, Profile::PqPure).expect("key");
        let t = (1u64 << 53) - 1;
        let spec = PublicationSpec {
            realm: [3; 32],
            topic: "io.macula/~aabbcc/craft/9f9f/command_applied_v1".into(),
            seq: t,
            published_at: t,
            payload: Payload::Clear(wire_payload("{}".into())),
            ttl_ms: None,
        };
        let publish = frame::sign_publish(&spec, &key).expect("signed");
        let now = i64::try_from(t).expect("fits");
        let int = Value::Int(i128::from(t));
        let ok = |f: &Value| frame::verify_publication(f, Profile::PqPure, now).is_ok();
        assert!(ok(&widest_event(&publish, int.clone())) && ok(&widest_gossip(&publish, int.clone())), "the widest forms are read");
        let longer_via = with(&publish, "event", vec![("delivered_via", Value::text("d".repeat(DELIVERED_VIA_BYTES + 1)))]);
        let longer_id = with(&publish, "plumtree_gossip", vec![("round", int.clone()), ("frame_id", Value::Bytes(vec![1; FRAME_ID_BYTES + 1]))]);
        assert!(!ok(&longer_via) && !ok(&longer_id), "and one byte more is refused");
    }

    /// A board's message as an app hands it to the seam, worst case: the
    /// message's own counters at their widest.
    fn envelope(kind: Kind) -> Message {
        Message { doc: "board-7c1e".into(), author: "aabbcc".into(), epoch: u64::MAX, seq: u64::MAX, sent_at_ms: u64::MAX, kind }
    }

    fn with_bytes(mut msg: Message, n: usize) -> Message {
        if let Some(bytes) = app_bytes(&mut msg.kind) {
            *bytes = vec![u8::MAX; n];
        }
        msg
    }

    /// The ±1 test of design r=3 M2 (r=4 inputs, r=5 frames): at the ceiling
    /// every frame the publication is read in fits, one byte more and the
    /// widest is over the cap.
    fn the_ceiling_is_exact(kind: Kind, profile: Profile) {
        let msg = envelope(kind);
        let prefix = transport_with(tokio::sync::mpsc::unbounded_channel().0, Arc::new(|| 0)).prefix.clone();
        let n = MeshTransport::largest_payload_that_fits(&prefix, profile, &msg).expect("measured");
        assert!(n > 0, "a frame carries some app bytes");
        let at = widest_received_len(with_bytes(msg.clone(), n), profile);
        let over = widest_received_len(with_bytes(msg, n + 1), profile);
        assert!(at <= MAX_FRAME_BYTES, "{n} app bytes make a {at}-byte frame, over the {MAX_FRAME_BYTES}-byte cap");
        assert!(over > MAX_FRAME_BYTES, "{} app bytes make a {over}-byte frame, still under the cap", n + 1);
    }

    #[test]
    fn a_command_at_the_ceiling_fits_and_one_byte_more_does_not() {
        the_ceiling_is_exact(Kind::Command { id: "board.server".into(), params: Vec::new(), anchor: None }, Profile::PqPure);
    }

    #[test]
    fn a_hybrid_key_has_its_own_ceiling() {
        the_ceiling_is_exact(Kind::Command { id: "board.server".into(), params: Vec::new(), anchor: None }, Profile::PqHybrid);
    }

    /// Another kind travels on another topic, of another length: the ceiling
    /// is measured on the one `send` picks.
    #[test]
    fn a_text_edit_is_measured_on_its_own_topic() {
        the_ceiling_is_exact(Kind::TextEdit { para: "p1".into(), update: Vec::new(), props: None }, Profile::PqPure);
    }

    #[test]
    fn a_kind_without_app_bytes_is_refused() {
        let msg = envelope(Kind::CursorMoved { position: None, name: None });
        let err = MeshTransport::largest_payload_that_fits("io.macula/~aabbcc/craft/9f9f", Profile::PqPure, &msg).expect_err("refused");
        assert!(err.contains("no app bytes"), "{err}");
    }
}
