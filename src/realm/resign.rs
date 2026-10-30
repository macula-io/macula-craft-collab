//! Ending this node's realm memberships: the signed `0x21` record the realm
//! acts on, and the read that proves the row **ended** rather than that the
//! record landed (macula-craft-collab#35, macula-realm#167).
//!
//! ## The record
//!
//! A resignation is one signed DHT record, type `0x21`, whose payload names the
//! realm and the member, both as text:
//!
//! - `realm_id` — the realm's **name** (`io.macula`, `net.beam-campus`), the
//!   only identifier a client can know. The realm resolves it to its own
//!   aggregate and refuses a record naming any realm but its own
//!   (macula-realm#169). A name is sent verbatim: the crate never derives an id.
//! - `member_did` — this node's 32-byte mesh identity as lowercase hex, which
//!   is what the realm decodes and compares against the record's own signer.
//!   The record is signed with this identity's key and no other, so the two
//!   always agree; a record that named another member would be refused
//!   `signer_mismatch` and end nothing.
//! - `resigned_at` — when the member says it left, milliseconds. Optional to
//!   the realm (absent means its own now); sent so the record says what it
//!   means.
//!
//! `created_at` comes from the record's own signed envelope, stamped when the
//! record is built, so a resignation is never refused `no_record_time` and is
//! never stale against the membership it names. **A record is never reused**:
//! every call builds a fresh one.
//!
//! ## The proof
//!
//! A record landing on a station says a station took it, not that the realm
//! acted. [`resign_one`] therefore reads the membership before it publishes
//! (pinning the row it is about), and polls the realm's membership read after
//! until it answers that this row ended. Anything else — `absent`, an error,
//! no answer inside the deadline — is [`ResignOutcome::Unverified`], which a
//! sweep must treat as failure. It never reports success it has not seen.

use std::time::Duration;

use macula_rust::cbor::Value;
use macula_rust::pool::Pool;
use macula_rust::record::{self, Record};
use serde_json::{Value as Json, json};

use super::realm_id_of;
use crate::identity::Identity;

/// The DHT record type the realm's resignation listener polls.
pub const RESIGN_RECORD_TYPE: u8 = 0x21;

/// The realm procedure a device proves itself to when it asks about its own
/// membership (macula-realm#167). The realm allowlists the procedures a proof
/// may carry, so this one is usable once the realm serves it.
pub const READ_MEMBERSHIP_PROCEDURE: &str = "macula_realm.read_realm_membership";

/// Where the realm serves that read: its member-facing host, the body
/// `{realm_id, member_did, proof}` (macula-realm#167).
pub const READ_MEMBERSHIP_PATH: &str = "/api/v1/memberships/status";

/// How long a resignation waits for the realm to answer that the row ended.
/// The listener polls every 30 seconds, so this leaves several polls.
pub const END_DEADLINE_MS: u64 = 90_000;

/// How often the membership read is asked while waiting.
pub const STATUS_POLL_MS: u64 = 15_000;

/// What the realm holds about one member's membership of one realm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MembershipStatus {
    /// The realm holds no row for this member and this realm: nothing to end.
    Absent,
    /// A live, admitted membership, admitted at this moment.
    Admitted { admitted_at_ms: u64 },
    /// An ended membership, ending this way at this moment.
    Ended { kind: EndKind, admitted_at_ms: u64, ended_at_ms: Option<u64> },
}

/// How a membership ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndKind {
    Resigned,
    Revoked,
}

/// What became of one identity's resignation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResignOutcome {
    /// The realm answered that the membership this call pinned has ended.
    Ended { realm: String, admitted_at_ms: u64, kind: EndKind },
    /// The record may have been published, but nothing proves the row ended:
    /// an absent answer, an error, or no answer in time. Never a pass.
    Unverified { realm: String, why: String },
}

/// Every outcome of one teardown, one entry per held membership.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResignReport {
    pub outcomes: Vec<ResignOutcome>,
}

impl ResignReport {
    /// Whether every held membership was proven ended.
    pub fn all_ended(&self) -> bool {
        !self.outcomes.is_empty() && self.outcomes.iter().all(|o| matches!(o, ResignOutcome::Ended { .. }))
    }

    /// Whether anything was not proven ended, or there was nothing to end.
    /// A sweep fails on this: an identity that ended nothing is not a pass.
    pub fn failed(&self) -> bool {
        !self.all_ended()
    }

    /// The realms this report covers.
    pub fn realms(&self) -> Vec<&str> {
        self.outcomes
            .iter()
            .map(|o| match o {
                ResignOutcome::Ended { realm, .. } | ResignOutcome::Unverified { realm, .. } => realm.as_str(),
            })
            .collect()
    }
}

/// The signed resignation record for `realm_name`, built now.
///
/// Signed with this identity's own key, which is the only key the realm accepts
/// for the member the payload names. Pure but for the key.
pub fn resign_record(identity: &Identity, realm_name: &str, resigned_at_ms: u64) -> Result<Record, String> {
    let payload = Value::Map(vec![
        (Value::text("realm_id"), Value::text(realm_name)),
        (Value::text("member_did"), Value::text(identity.node_id())),
        (Value::text("resigned_at"), Value::Int(i128::from(resigned_at_ms))),
    ]);
    let unsigned = record::envelope(RESIGN_RECORD_TYPE, payload, None, 0).map_err(|e| format!("resignation envelope: {e:?}"))?;
    record::sign(&unsigned, &identity.key()).map_err(|e| format!("resignation sign: {e:?}"))
}

/// The realm's answer, parsed: what it holds about this node's membership.
///
/// A non-2xx answer is an **error**, not an `Absent`: the realm answers 503 for
/// a projection it cannot read precisely so a sweep never reads "I could not
/// tell" as "there is nothing there" (macula-realm#167). An answer naming no
/// status, a status this crate does not know, or an ended membership with no
/// admission moment is an error for the same reason.
pub fn parse_status(status_code: i32, body: &str) -> Result<MembershipStatus, String> {
    if !(200..300).contains(&status_code) {
        return Err(format!("the realm answered HTTP {status_code}: {body}"));
    }
    let answer: Json = serde_json::from_str(body).map_err(|e| format!("the realm answered no JSON: {e}"))?;
    status_from_answer(&answer)
}

/// [`parse_status`] on an already-parsed answer. Pure.
fn status_from_answer(answer: &Json) -> Result<MembershipStatus, String> {
    let status = text(answer, "status").ok_or("the realm answered no membership status")?;
    match status.as_str() {
        "admitted" => admitted_at(answer).map(|admitted_at_ms| MembershipStatus::Admitted { admitted_at_ms }),
        "resigned" => ended_from(answer, EndKind::Resigned),
        "revoked" => ended_from(answer, EndKind::Revoked),
        "absent" => Ok(MembershipStatus::Absent),
        other => Err(format!("the realm answered an unknown membership status {other:?}")),
    }
}

/// The moment a membership was admitted, which every answered status carries.
fn admitted_at(answer: &Json) -> Result<u64, String> {
    moment(answer, "admitted_at").ok_or_else(|| "the realm answered no admitted_at".to_string())
}

/// An ended membership: the admission moment it ended, and how.
fn ended_from(answer: &Json, kind: EndKind) -> Result<MembershipStatus, String> {
    let admitted_at_ms = admitted_at(answer)?;
    let ended_at_ms = moment(answer, "resigned_at").or_else(|| moment(answer, "revoked_at"));
    Ok(MembershipStatus::Ended { kind, admitted_at_ms, ended_at_ms })
}

/// A text field of the realm's answer.
fn text(answer: &Json, name: &str) -> Option<String> {
    answer.get(name).and_then(Json::as_str).map(str::to_string)
}

/// A moment of the realm's answer, in milliseconds. A value sent as text is
/// refused rather than parsed: a shape this crate did not ask for is not one
/// to guess at.
fn moment(answer: &Json, name: &str) -> Option<u64> {
    answer.get(name).and_then(Json::as_i64).and_then(|ms| u64::try_from(ms).ok())
}

/// Whether the ended answer is about the membership this call pinned.
///
/// `None` means "not yet": the row is still admitted and the caller keeps
/// polling. Everything else is decided here, so the rule that `absent` is red
/// lives in one place and is tested.
pub fn outcome_for(realm: &str, pinned: &MembershipStatus, answer: &MembershipStatus) -> Option<ResignOutcome> {
    let unverified = |why: &str| Some(ResignOutcome::Unverified { realm: realm.to_string(), why: why.to_string() });
    let MembershipStatus::Admitted { admitted_at_ms: pinned_at } = *pinned else {
        return unverified("nothing was admitted to end");
    };
    match *answer {
        MembershipStatus::Admitted { .. } => None,
        MembershipStatus::Absent => unverified("the realm answers absent: no row, which is red, never a pass"),
        MembershipStatus::Ended { kind, admitted_at_ms, .. } if admitted_at_ms == pinned_at => {
            Some(ResignOutcome::Ended { realm: realm.to_string(), admitted_at_ms, kind })
        }
        MembershipStatus::Ended { admitted_at_ms, .. } => {
            unverified(&format!("the realm ended a membership admitted at {admitted_at_ms}, not the pinned {pinned_at}"))
        }
    }
}

/// Publishes this node's resignation of one realm and waits for the realm to
/// answer that the row ended.
///
/// Reads the membership first, so the answer is matched against the row this
/// call is about; publishes a fresh record; then polls until the realm says
/// that row ended. A membership that is not there is not published for: there
/// is nothing to end, and the outcome says so.
pub async fn resign_one(pool: &Pool, identity: &Identity, realm_name: &str, deadline: Duration) -> ResignOutcome {
    let pinned = match read_membership(identity, realm_name, super::now_ms()).await {
        Ok(status) => status,
        Err(why) => return ResignOutcome::Unverified { realm: realm_name.to_string(), why: format!("reading the membership first: {why}") },
    };
    let now_ms = super::now_ms();
    match pinned {
        // An earlier run ended this membership and died before forgetting the
        // credential. Nothing is ended now, and the credential goes: left in
        // place it is what the next start would renew, and renewing re-admits.
        MembershipStatus::Ended { .. } => {
            super::forget_credential(identity.node_id(), realm_name);
            ResignOutcome::Unverified { realm: realm_name.to_string(), why: "already ended before this run: nothing was ended now".into() }
        }
        // `absent` is red, not "nothing to do": the realm erases rows
        // (reprojection, the test realm's reset), so an absent answer is also
        // what a mis-keyed resignation looks like.
        MembershipStatus::Absent => {
            ResignOutcome::Unverified { realm: realm_name.to_string(), why: "the realm answers absent: no row to end".into() }
        }
        // A realm clock ahead of this one would make the record's signed
        // moment older than the admission it is meant to end, and the realm
        // refuses that as stale. Waiting is not this call's business.
        MembershipStatus::Admitted { admitted_at_ms } if admitted_at_ms > now_ms => ResignOutcome::Unverified {
            realm: realm_name.to_string(),
            why: format!("the realm admits this membership at {admitted_at_ms}, ahead of this machine's clock ({now_ms})"),
        },
        pinned @ MembershipStatus::Admitted { .. } => {
            if let Err(why) = publish(pool, identity, realm_name, now_ms).await {
                return ResignOutcome::Unverified { realm: realm_name.to_string(), why };
            }
            await_end(identity, realm_name, pinned, deadline).await
        }
    }
}

/// Builds, signs and puts one fresh resignation record.
async fn publish(pool: &Pool, identity: &Identity, realm_name: &str, now_ms: u64) -> Result<(), String> {
    let signed = resign_record(identity, realm_name, now_ms)?;
    let wire = record::encode(&signed).map_err(|e| format!("resignation encode: {e:?}"))?;
    pool.put_record(&wire).await.map_err(|e| format!("resignation put_record: {e:?}"))
}

/// Polls the realm until the pinned row is answered ended, or the deadline
/// passes. A row still admitted is waited for; every other answer is decided
/// by [`outcome_for`].
async fn await_end(identity: &Identity, realm_name: &str, pinned: MembershipStatus, deadline: Duration) -> ResignOutcome {
    let started = std::time::Instant::now();
    loop {
        let answer = read_membership(identity, realm_name, super::now_ms()).await;
        if let Ok(answer) = &answer
            && let Some(outcome) = outcome_for(realm_name, &pinned, answer)
        {
            return outcome;
        }
        if started.elapsed() >= deadline {
            return ResignOutcome::Unverified {
                realm: realm_name.to_string(),
                why: format!("no ended answer within {}ms (last answer: {answer:?})", deadline.as_millis()),
            };
        }
        tokio::time::sleep(Duration::from_millis(STATUS_POLL_MS)).await;
    }
}

/// Asks the realm what it holds about this node's membership of `realm_name`:
/// a device-signed read of the caller's own row (macula-realm#167).
pub async fn read_membership(identity: &Identity, realm_name: &str, now_ms: u64) -> Result<MembershipStatus, String> {
    let identity = identity.clone();
    let realm_name = realm_name.to_string();
    // The realm's transport is blocking; the transport's own runtime is not
    // this call's to stall for ten seconds.
    tokio::task::spawn_blocking(move || post_status(&realm_name, &identity, now_ms)).await.map_err(|e| format!("membership read: {e}"))?
}

/// The read's body: `{realm_id, member_did, public_key}`, which is exactly
/// what the device signs; the proof is added to it afterwards (macula-realm#167).
///
/// The carried key travels with the request as the join body carries it: a node
/// id cannot be turned back into a key, so the realm verifies the proof with
/// this key and then holds `member_did` to the node id it derives from it.
pub fn status_body(identity: &Identity, realm_name: &str) -> Json {
    use base64::Engine as _;
    let public_key = base64::engine::general_purpose::STANDARD.encode(identity.carried_key());
    json!({"realm_id": realm_name, "member_did": identity.node_id(), "public_key": public_key})
}

/// One blocking POST of the proof-signed membership read. The signed body is
/// `{realm_id, member_did}`, so the realm a read is about is inside the proof
/// and cannot be swapped for another on the way.
pub fn post_status(realm_name: &str, identity: &Identity, now_ms: u64) -> Result<MembershipStatus, String> {
    let body = status_body(identity, realm_name);
    let request = super::proof::canonical_json(&body)?;
    let proof = identity.device_request_proof(&realm_id_of(realm_name), READ_MEMBERSHIP_PROCEDURE, &request, now_ms)?;
    let mut signed = body;
    signed["proof"] = proof.to_json();
    let url = format!("{}{}", super::session::realm_base_url(realm_name), READ_MEMBERSHIP_PATH);
    let res = minreq::post(&url)
        .with_header("content-type", "application/json")
        .with_header("accept", "application/json")
        .with_body(signed.to_string())
        .with_timeout(10)
        .send()
        .map_err(|e| format!("{url}: {e}"))?;
    let text = res.as_str().map_err(|e| format!("{url}: {e}"))?;
    parse_status(i32::from(res.status_code), text)
}

/// Resigns every membership this node holds: every realm in
/// [`super::list_credentials`], not only the one a transport was configured
/// for. One realm's failure does not stop the others — the report carries
/// what happened to each, and any [`ResignOutcome::Unverified`] makes it
/// failed.
pub async fn resign_all(pool: &Pool, identity: &Identity, credentials: &[super::RealmCredential], deadline: Duration) -> ResignReport {
    let mut report = ResignReport::default();
    for held in credentials {
        report.outcomes.push(resign_one(pool, identity, &held.realm, deadline).await);
    }
    report
}

/// Whether this process should resign its memberships when its transport
/// stops (`MACULA_CRAFT_RESIGN_ON_SHUTDOWN=1`).
///
/// Off by default and deliberately so: a person closing an app must not leave
/// their realm, while a harness identity must. Only a sweep turns it on.
pub fn resign_on_shutdown() -> bool {
    matches!(std::env::var("MACULA_CRAFT_RESIGN_ON_SHUTDOWN").as_deref(), Ok("1") | Ok("true"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The crate carries one profile: identity keys are pq_hybrid, the same
    /// key a transport links with.
    const PROFILE: &str = "pq_hybrid";

    fn identity() -> Identity {
        let dir = tempfile::tempdir().expect("dir").keep();
        Identity::load_or_create_at(PROFILE, "resign-test", "Resign", &dir).expect("identity")
    }

    /// A text field of the record's CBOR payload.
    fn payload_text(payload: &Value, key: &str) -> Option<String> {
        let Value::Map(entries) = payload else { return None };
        let (_, value) = entries.iter().find(|(k, _)| matches!(k, Value::Text(t) if t == key))?;
        match value {
            Value::Text(t) => Some(t.clone()),
            _ => None,
        }
    }

    /// An integer field of the record's CBOR payload.
    fn payload_int(payload: &Value, key: &str) -> Option<i128> {
        let Value::Map(entries) = payload else { return None };
        let (_, value) = entries.iter().find(|(k, _)| matches!(k, Value::Text(t) if t == key))?;
        match value {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    #[test]
    fn the_record_is_a_signed_0x21_naming_the_realm_and_the_member() {
        let identity = identity();
        let record = resign_record(&identity, "net.beam-campus", 1_760_000_000_000).expect("record");
        assert_eq!(record.record_type.0, RESIGN_RECORD_TYPE);
        assert!(record.created_at > 1_000_000_000_000, "the envelope stamps its own moment");
        assert!(record.expires_at > record.created_at, "a record with no life would be refused");
        assert_eq!(payload_text(&record.payload, "realm_id").as_deref(), Some("net.beam-campus"));
        assert_eq!(payload_text(&record.payload, "member_did"), Some(identity.node_id().to_string()));
        assert_eq!(payload_int(&record.payload, "resigned_at"), Some(1_760_000_000_000));
        let wire = record::encode(&record).expect("wire");
        let verified = record::verify(&wire, identity.profile(), record.created_at as i64).expect("the record verifies");
        assert_eq!(verified.record().record_type.0, RESIGN_RECORD_TYPE);
    }

    #[test]
    fn a_record_that_does_not_match_its_signer_is_refused_by_the_rule_the_realm_uses() {
        let identity = identity();
        let other_dir = tempfile::tempdir().expect("dir").keep();
        let other = Identity::load_or_create_at(PROFILE, "resign-other", "Other", &other_dir).expect("identity");
        let record = resign_record(&identity, "net.beam-campus", 1_760_000_000_000).expect("record");
        let named = payload_text(&record.payload, "member_did").expect("member_did");
        assert_ne!(named, other.node_id(), "another key's record names another member: the realm's signer check has something to refuse");
        let mut tampered = record::encode(&record).expect("wire");
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(record::verify(&tampered, identity.profile(), record.created_at as i64).is_err(), "a changed byte does not verify");
    }

    #[test]
    fn the_realm_answers_parse_and_an_unreadable_answer_is_an_error_not_an_absence() {
        let ok = |body: &str| parse_status(200, body);
        let admitted = ok(r#"{"status":"admitted","admitted_at":1000}"#);
        assert_eq!(admitted, Ok(MembershipStatus::Admitted { admitted_at_ms: 1_000 }));
        let resigned = ok(r#"{"status":"resigned","admitted_at":1000,"resigned_at":2000}"#);
        assert_eq!(resigned, Ok(MembershipStatus::Ended { kind: EndKind::Resigned, admitted_at_ms: 1_000, ended_at_ms: Some(2_000) }));
        let revoked = ok(r#"{"status":"revoked","admitted_at":1000,"revoked_at":3000}"#);
        assert_eq!(revoked, Ok(MembershipStatus::Ended { kind: EndKind::Revoked, admitted_at_ms: 1_000, ended_at_ms: Some(3_000) }));
        assert_eq!(ok(r#"{"status":"absent"}"#), Ok(MembershipStatus::Absent));
        assert!(ok(r#"{"status":"error"}"#).is_err(), "an unknown status is not absent");
        assert!(ok(r#"{}"#).is_err(), "no status is not absent");
        assert!(ok(r#"{"status":"resigned"}"#).is_err(), "an ended answer without its moment is not readable");
        assert!(ok(r#"{"status":"admitted","admitted_at":"yesterday"}"#).is_err(), "a moment sent as text is not parsed into one");
        assert!(ok("not json").is_err(), "a body that is not JSON is an error");
        for code in [401, 403, 404, 503] {
            assert!(parse_status(code, r#"{"status":"absent"}"#).is_err(), "HTTP {code} is an error even when the body says absent");
        }
    }

    #[test]
    fn the_read_body_carries_the_realm_the_member_and_the_carried_key() {
        use base64::Engine as _;
        let identity = identity();
        let body = status_body(&identity, "net.beam-campus");
        assert_eq!(body["realm_id"], "net.beam-campus", "the realm is named: the realm resolves it, or refuses it");
        assert_eq!(body["member_did"], identity.node_id(), "the member is named by its own node id");
        let carried = base64::engine::general_purpose::STANDARD.encode(identity.carried_key());
        assert_eq!(body["public_key"], carried, "the key travels as the join body carries it: a node id cannot be turned back into one");
        assert!(body.get("proof").is_none(), "the proof is added after signing, never signed itself");
    }

    #[test]
    fn absent_an_error_and_another_membership_are_never_a_pass() {
        let pinned = MembershipStatus::Admitted { admitted_at_ms: 1_000 };
        let ended = MembershipStatus::Ended { kind: EndKind::Resigned, admitted_at_ms: 1_000, ended_at_ms: Some(2_000) };
        assert!(matches!(outcome_for("net.beam-campus", &pinned, &ended), Some(ResignOutcome::Ended { .. })));
        for answer in [
            MembershipStatus::Absent,
            MembershipStatus::Ended { kind: EndKind::Resigned, admitted_at_ms: 2_000, ended_at_ms: None },
            MembershipStatus::Ended { kind: EndKind::Revoked, admitted_at_ms: 7, ended_at_ms: None },
        ] {
            assert!(matches!(outcome_for("net.beam-campus", &pinned, &answer), Some(ResignOutcome::Unverified { .. })), "{answer:?} must not pass");
        }
        assert_eq!(outcome_for("net.beam-campus", &pinned, &pinned), None, "still admitted: keep polling");
        assert!(matches!(outcome_for("net.beam-campus", &MembershipStatus::Absent, &ended), Some(ResignOutcome::Unverified { .. })));
    }

    #[test]
    fn a_report_that_lost_one_membership_fails() {
        let ended = ResignOutcome::Ended { realm: "net.beam-campus".into(), admitted_at_ms: 1, kind: EndKind::Resigned };
        let unverified = ResignOutcome::Unverified { realm: "io.macula".into(), why: "absent".into() };
        assert!(ResignReport { outcomes: vec![ended.clone()] }.all_ended());
        let mixed = ResignReport { outcomes: vec![ended, unverified] };
        assert!(mixed.failed(), "one unverified membership fails the teardown");
        assert_eq!(mixed.realms(), vec!["net.beam-campus", "io.macula"]);
        assert!(ResignReport::default().failed(), "a teardown that ended nothing is not a pass");
    }
}
