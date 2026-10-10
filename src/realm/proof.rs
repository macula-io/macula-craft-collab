//! Realm proof v2 (macula-realm#29): the device proves it holds its own key
//! for exactly this request to this realm, once.
//!
//! Everything gated on it — creating a join session, minting a membership
//! UCAN — would otherwise let anyone name any device key and receive a
//! realm-signed credential. This is the client half, mirrored from the
//! realm's own verification (`MaculaRealm.Identity.DeviceRequestProof`) and
//! pinned byte-for-byte by its checked-in cross-SDK vector
//! (`tests/vectors/device_request_proof_vector.hex`).
//!
//! ## The signed message
//!
//! Deterministic CBOR (macula's own canonical encoder, via
//! `macula_rust::cbor`) of a map with text keys: `tag` (the text
//! `macula.realm.device_request`), `v` (2), `public_key` (the carried key,
//! bytes), `realm` (32 bytes), `procedure` (text), `timestamp`
//! (milliseconds), `nonce` (16 bytes), `request` (every field of the request
//! except the proof — and never `caller`, which the station merges).

use macula_rust::cbor::{self, Value};

/// The proof's tag; a different tag can never be replayed as this proof.
pub const DEVICE_REQUEST_TAG: &str = "macula.realm.device_request";
/// The proof's layout version.
pub const DEVICE_REQUEST_VERSION: u64 = 2;
/// The realm's accepted clock skew: a proof older than this is stale.
pub const PROOF_SKEW_MS: u64 = 60_000;

/// The procedure names a proof may carry (the realm refuses any other).
pub const JOIN_SESSION_PROCEDURE: &str = "macula_realm.join_session";
pub const MEMBERSHIP_UCAN_PROCEDURE: &str = "macula_realm.membership_ucan";

/// A realm proof v2, as the wire carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRequestProof {
    pub timestamp_ms: u64,
    pub nonce: [u8; 16],
    pub signature: Vec<u8>,
}

impl DeviceRequestProof {
    /// The proof as JSON carries it (the join-session path).
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "v": DEVICE_REQUEST_VERSION,
            "timestamp": self.timestamp_ms,
            "nonce": hex::encode(self.nonce),
            "signature": hex::encode(&self.signature),
        })
    }

    /// The proof as the mesh codec carries it (the same fields, CBOR).
    pub fn to_cbor(&self) -> Value {
        Value::Map(vec![
            (Value::text("v"), Value::Int(DEVICE_REQUEST_VERSION as i128)),
            (
                Value::text("timestamp"),
                Value::Int(self.timestamp_ms as i128),
            ),
            (Value::text("nonce"), Value::text(hex::encode(self.nonce))),
            (
                Value::text("signature"),
                Value::text(hex::encode(&self.signature)),
            ),
        ])
    }
}

/// The exact bytes a device signs: deterministic CBOR of the tagged map.
pub fn device_request_message(
    public_key: &[u8],
    realm_id: &[u8; 32],
    procedure: &str,
    timestamp_ms: u64,
    nonce: &[u8; 16],
    request: &Value,
) -> Result<Vec<u8>, String> {
    let message = Value::Map(vec![
        (Value::text("tag"), Value::text(DEVICE_REQUEST_TAG)),
        (Value::text("v"), Value::Int(DEVICE_REQUEST_VERSION as i128)),
        (Value::text("public_key"), Value::Bytes(public_key.to_vec())),
        (Value::text("realm"), Value::Bytes(realm_id.to_vec())),
        (Value::text("procedure"), Value::text(procedure)),
        (Value::text("timestamp"), Value::Int(timestamp_ms as i128)),
        (Value::text("nonce"), Value::Bytes(nonce.to_vec())),
        (Value::text("request"), request.clone()),
    ]);
    cbor::encode(&message).map_err(|e| e.to_string())
}

/// The mesh rule: the payload as the handler receives it, minus the proof
/// and minus `caller` in every key form. The signed request keeps every
/// value exactly as it goes on the wire.
pub fn canonical_mesh(payload: &Value) -> Value {
    payload.without(&["proof", "caller"])
}

/// The pinned JSON rule (the realm's `json_request/1`): what a JSON body
/// means before it is signed. A string is text; an integral number is an
/// integer (so 1 and 1.0 are the same); any other number is a float; an
/// object is a map; an array is a list; null is null; a boolean — or an
/// integer beyond 2^53-1 — is refused.
pub fn canonical_json(value: &serde_json::Value) -> Result<Value, String> {
    match value {
        serde_json::Value::Bool(_) => Err("boolean_not_allowed".into()),
        serde_json::Value::Null => Ok(Value::Null),
        serde_json::Value::String(s) => Ok(Value::Text(s.clone())),
        serde_json::Value::Number(n) => canonical_number(n),
        serde_json::Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(canonical_json(item)?);
            }
            Ok(Value::List(out))
        }
        serde_json::Value::Object(map) => {
            let mut out = Vec::with_capacity(map.len());
            for (k, v) in map {
                out.push((Value::Text(k.clone()), canonical_json(v)?));
            }
            Ok(Value::Map(out))
        }
    }
}

const MAX_SAFE_INTEGER: i128 = 9_007_199_254_740_991;

fn canonical_number(n: &serde_json::Number) -> Result<Value, String> {
    if let Some(i) = n.as_i64() {
        return in_range(i as i128);
    }
    if let Some(u) = n.as_u64() {
        return in_range(u as i128);
    }
    let f = n
        .as_f64()
        .ok_or_else(|| "unrepresentable number".to_string())?;
    if !f.is_finite() {
        return Err("number_out_of_range".into());
    }
    // The realm's rule: an integral float is an integer (100.0 -> 100,
    // -0.0 -> 0); anything else stays a float64.
    if f.fract() == 0.0 {
        let i = f.trunc();
        if i.abs() > MAX_SAFE_INTEGER as f64 {
            return Err("number_out_of_range".into());
        }
        return Ok(Value::Int(i as i128));
    }
    Ok(Value::Float(f))
}

fn in_range(i: i128) -> Result<Value, String> {
    if i.abs() > MAX_SAFE_INTEGER {
        return Err("number_out_of_range".into());
    }
    Ok(Value::Int(i))
}

/// Verifies a proof the way the realm does, for tests and mock realms:
/// version, freshness, and the signature over the reconstructed message.
pub fn verify_device_request(
    public_key: &[u8],
    realm_id: &[u8; 32],
    procedure: &str,
    request: &Value,
    proof: &DeviceRequestProof,
    now_ms: u64,
) -> Result<(), String> {
    let skew = now_ms.abs_diff(proof.timestamp_ms);
    if skew > PROOF_SKEW_MS {
        return Err("stale_proof".into());
    }
    let message = device_request_message(
        public_key,
        realm_id,
        procedure,
        proof.timestamp_ms,
        &proof.nonce,
        request,
    )?;
    if !macula_rust::node_key::verify(
        &message,
        &proof.signature,
        public_key,
        macula_rust::profile::Profile::PqHybrid,
    ) {
        return Err("bad_proof".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The realm's checked-in cross-SDK vector (macula-realm,
    /// device_request_proof_test.exs "the cross-SDK vector"): these exact
    /// inputs must encode to these exact bytes, or signatures made here
    /// will not verify there.
    #[test]
    fn the_realm_vector_pins_the_message_bytes() {
        let public_key = vec![7u8; 2592];
        let realm_id: [u8; 32] =
            hex::decode("abb81b5a614b63551b400b810648c0c8a78efad845442630c94b46cc95d2fcd1")
                .expect("realm hex")
                .try_into()
                .expect("32 bytes");
        let request = canonical_json(&serde_json::json!({
            "device_info": {"hostname": "laptop.local", "note": null},
            "n": 100.0,
            "z": -0.0,
            "f": 1.5,
        }))
        .expect("canonical");
        let message = device_request_message(
            &public_key,
            &realm_id,
            JOIN_SESSION_PROCEDURE,
            1_790_000_000_000,
            &[0u8; 16],
            &request,
        )
        .expect("message");
        let vector = include_str!("../../tests/vectors/device_request_proof_vector.hex").trim();
        assert_eq!(
            hex::encode(&message),
            vector,
            "the message must match the realm's vector byte for byte"
        );
    }

    #[test]
    fn the_json_rule_is_the_realms_rule() {
        assert!(
            canonical_json(&serde_json::json!(true)).is_err(),
            "booleans are refused"
        );
        assert!(
            canonical_json(&serde_json::json!(9_007_199_254_740_992u64)).is_err(),
            "beyond 2^53-1 is refused"
        );
        assert_eq!(
            canonical_json(&serde_json::json!(100.0)).expect("100.0"),
            Value::Int(100)
        );
        assert_eq!(
            canonical_json(&serde_json::json!(-0.0)).expect("-0.0"),
            Value::Int(0)
        );
        assert_eq!(
            canonical_json(&serde_json::json!(1.5)).expect("1.5"),
            Value::Float(1.5)
        );
        assert_eq!(
            canonical_json(&serde_json::json!(null)).expect("null"),
            Value::Null
        );
        assert_eq!(
            canonical_json(&serde_json::json!("x")).expect("text"),
            Value::Text("x".into())
        );
        assert_eq!(
            canonical_json(&serde_json::json!(7)).expect("7"),
            Value::Int(7)
        );
    }

    #[test]
    fn caller_and_proof_are_never_signed() {
        let payload = Value::Map(vec![
            (Value::text("public_key"), Value::text("AAAA")),
            (Value::text("proof"), Value::text("whatever")),
            (Value::text("caller"), Value::text("someone")),
        ]);
        assert_eq!(
            canonical_mesh(&payload),
            Value::Map(vec![(Value::text("public_key"), Value::text("AAAA"))]),
        );
    }

    #[test]
    fn a_tampered_request_or_realm_does_not_verify() {
        let public_key = vec![7u8; 2592];
        let realm_id = [9u8; 32];
        let request =
            canonical_json(&serde_json::json!({"public_key": "AAAA"})).expect("canonical");
        let message = device_request_message(
            &public_key,
            &realm_id,
            MEMBERSHIP_UCAN_PROCEDURE,
            1_000,
            &[1u8; 16],
            &request,
        )
        .expect("message");
        let proof = DeviceRequestProof {
            timestamp_ms: 1_000,
            nonce: [1u8; 16],
            signature: b"not-a-real-signature".to_vec(),
        };
        // A forged signature is refused (the real key never signed it).
        assert!(
            verify_device_request(
                &public_key,
                &realm_id,
                MEMBERSHIP_UCAN_PROCEDURE,
                &request,
                &proof,
                1_000
            )
            .is_err()
        );
        // A proof older than the skew is stale, signature or not.
        assert!(
            verify_device_request(
                &public_key,
                &realm_id,
                MEMBERSHIP_UCAN_PROCEDURE,
                &request,
                &proof,
                1_000 + PROOF_SKEW_MS + 1
            )
            .is_err()
        );
        // The message is realm- and procedure-bound: other inputs move the bytes.
        let other = device_request_message(
            &public_key,
            &[8u8; 32],
            MEMBERSHIP_UCAN_PROCEDURE,
            1_000,
            &[1u8; 16],
            &request,
        )
        .expect("message");
        assert_ne!(message, other);
        let other = device_request_message(
            &public_key,
            &realm_id,
            JOIN_SESSION_PROCEDURE,
            1_000,
            &[1u8; 16],
            &request,
        )
        .expect("message");
        assert_ne!(message, other);
    }
}
