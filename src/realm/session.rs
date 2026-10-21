//! The realm's citizen join session, over HTTP: create a session (a link the
//! person opens and confirms after signing in), poll it, and turn a
//! confirmation into the stored credential.
//!
//! The session request carries a realm proof v2 over exactly the body sent
//! (minus the proof), so the realm refuses a request changed on the way —
//! the same proof the mesh path carries, through the pinned JSON rule.

use serde_json::{Value as Json, json};

use crate::identity::Identity;
use crate::realm::proof::{self, DeviceRequestProof, JOIN_SESSION_PROCEDURE};

/// Makes aws-lc-rs the process's TLS provider before the first HTTPS call. The mesh stack
/// compiles rustls' ring provider in too, and with two providers rustls picks none, so
/// minreq's `ClientConfig::builder()` would panic. A provider installed earlier stands.
fn tls_ready() {
    static TLS: std::sync::Once = std::sync::Once::new();
    TLS.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// The realm service origin for a realm name: `io.macula` ->
/// `https://realm.macula.io` (realm labels reversed, `realm.` prefixed).
pub fn realm_base_url(realm_name: &str) -> String {
    let reversed: Vec<&str> = realm_name.split('.').rev().collect();
    format!("https://realm.{}", reversed.join("."))
}

/// A created join session: the link the person opens (or scans).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreatedSession {
    pub session_id: String,
    pub join_url: String,
    pub expires_at: String,
}

/// A poll's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionStatus {
    Pending { expires_at: String },
    Confirmed(ConfirmedSession),
    Expired,
    Error(String),
}

/// A confirmed join session: the membership material the realm issued. The
/// realm's controller sends `{status, org_identity, cert_pem, citizen_did,
/// ucan}`; `refresh_token` is empty on that path and `account` absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfirmedSession {
    pub refresh_token: String,
    pub org_identity: String,
    pub cert_pem: Option<String>,
    pub account: Option<String>,
    pub citizen_did: Option<String>,
    pub ucan: Option<String>,
}

/// The join-session request body the proof signs: this node's carried key
/// and what makes the device recognisable to the person confirming it.
pub fn join_request_body(identity: &Identity) -> Json {
    use base64::Engine as _;
    json!({
        "public_key": base64::engine::general_purpose::STANDARD.encode(identity.carried_key()),
        "device_info": {
            "os": format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
            "version": format!("craft-collab {}", env!("CARGO_PKG_VERSION")),
            "client": "craft",
        },
    })
}

/// Creates a join session: POSTs the proof-signed body and returns the link.
pub fn create_session(realm_name: &str, base_url: &str, identity: &Identity, now_ms: u64) -> Result<CreatedSession, String> {
    let body = join_request_body(identity);
    let request = proof::canonical_json(&body)?;
    let proof = identity
        .device_request_proof(&crate::realm::realm_id_of(realm_name), JOIN_SESSION_PROCEDURE, &request, now_ms)
        .map_err(|e| format!("proof: {e}"))?;
    post_join_session(base_url, &with_proof(body, &proof))
}

/// POSTs the prepared body; see [`create_session`].
pub fn post_join_session(base_url: &str, body: &Json) -> Result<CreatedSession, String> {
    let url = format!("{}/api/v1/join/sessions", base_url.trim_end_matches('/'));
    tls_ready();
    let res = minreq::post(&url)
        .with_header("content-type", "application/json")
        .with_header("accept", "application/json")
        .with_body(body.to_string())
        .with_timeout(10)
        .send()
        .map_err(|e| format!("{url}: {e}"))?;
    let text = res.as_str().map_err(|e| format!("{url}: {e}"))?;
    parse_created(i32::from(res.status_code), text)
}

/// Shapes a create reply (2xx with `session_id`/`join_url`) or a refusal.
pub fn parse_created(status: i32, body: &str) -> Result<CreatedSession, String> {
    let parsed: Json = serde_json::from_str(body).unwrap_or(Json::Null);
    let field = |name: &str| parsed.get(name).and_then(Json::as_str).map(str::to_string);
    if (200..300).contains(&status)
        && let (Some(session_id), Some(join_url)) = (field("session_id"), field("join_url"))
    {
        return Ok(CreatedSession { session_id, join_url, expires_at: field("expires_at").unwrap_or_default() });
    }
    Err(format!("realm refused to create a join session (HTTP {status}): {body}"))
}

/// Polls a session: pending, confirmed, expired, or an error.
pub fn poll_session(base_url: &str, session_id: &str) -> Result<SessionStatus, String> {
    let url = format!("{}/api/v1/join/sessions/{}", base_url.trim_end_matches('/'), urlencode(session_id));
    tls_ready();
    let res = minreq::get(&url).with_header("accept", "application/json").with_timeout(10).send().map_err(|e| format!("{url}: {e}"))?;
    let text = res.as_str().map_err(|e| format!("{url}: {e}"))?;
    Ok(parse_session_status(i32::from(res.status_code), text))
}

/// Shapes a poll reply. Pure.
pub fn parse_session_status(status: i32, body: &str) -> SessionStatus {
    let parsed: Json = serde_json::from_str(body).unwrap_or(Json::Null);
    let field = |name: &str| parsed.get(name).and_then(Json::as_str).map(str::to_string);
    if status == 410 || field("error").as_deref() == Some("session_expired") {
        return SessionStatus::Expired;
    }
    if status == 200 && field("status").as_deref() == Some("pending") {
        return SessionStatus::Pending { expires_at: field("expires_at").unwrap_or_default() };
    }
    // The realm's controller renders a confirmed session as {status,
    // org_identity, cert_pem, citizen_did, ucan}: org_identity is always
    // present, the rest are optional, and there is no refresh_token on this
    // path (found live; the mock had drifted from the controller).
    if status == 200
        && field("status").as_deref() == Some("confirmed")
        && let Some(org_identity) = field("org_identity")
    {
        return SessionStatus::Confirmed(ConfirmedSession {
            refresh_token: field("refresh_token").unwrap_or_default(),
            org_identity,
            cert_pem: field("cert_pem"),
            account: field("oauth_account"),
            citizen_did: field("citizen_did"),
            ucan: field("ucan"),
        });
    }
    SessionStatus::Error(format!("realm answered HTTP {status}: {body}"))
}

/// The credential a confirmation leaves: a citizen-tier membership, strictly
/// stronger than the device-tier one.
pub fn credential_from_confirmed(
    identity: &Identity,
    realm_name: &str,
    portal: &str,
    confirmed: ConfirmedSession,
    now_ms: u64,
) -> crate::realm::RealmCredential {
    crate::realm::RealmCredential {
        node_id: identity.node_id().to_string(),
        realm: realm_name.to_string(),
        portal: portal.to_string(),
        org_identity: confirmed.org_identity,
        account: confirmed.account,
        cert_pem: confirmed.cert_pem,
        refresh_token: confirmed.refresh_token,
        joined_at_ms: now_ms,
        citizen_did: confirmed.citizen_did,
        ucan: confirmed.ucan,
        tier: crate::realm::Tier::Citizen,
    }
}

fn with_proof(body: Json, proof: &DeviceRequestProof) -> Json {
    let mut body = body;
    if let Some(map) = body.as_object_mut() {
        map.insert("proof".into(), proof.to_json());
    }
    body
}

/// Percent-encodes a session id for the status URL (they are opaque).
fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
            other => format!("%{other:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    use macula_rust::profile::Profile;

    use super::*;

    #[test]
    fn https_has_a_tls_provider_beside_the_mesh_stack() {
        // ring (from the mesh stack) and aws-lc-rs (minreq's) are both compiled in; without
        // tls_ready, rustls picks neither and minreq's ClientConfig::builder() panics.
        tls_ready();
        let config = rustls::ClientConfig::builder().with_root_certificates(rustls::RootCertStore::empty()).with_no_client_auth();
        assert!(!config.crypto_provider().cipher_suites.is_empty());
    }

    fn identity(dir: &std::path::Path) -> Identity {
        Identity::load_or_create_with(Profile::PqHybrid, "joiner", "Joiner", None, Some(dir)).expect("identity")
    }

    /// A mock realm: verifies the posted proof exactly as the realm does
    /// (canonical JSON rule, signature, skew), then answers pending once and
    /// confirmed after. Any failure is a 4xx with the reason.
    fn mock_realm(realm_name: &str, public_key: Vec<u8>) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let log = Arc::new(Mutex::new(Vec::new()));
        let seen = log.clone();
        let realm_id = crate::realm::realm_id_of(realm_name);
        std::thread::spawn(move || serve_connections(listener, realm_id, public_key, seen));
        (format!("http://{addr}"), log)
    }

    /// Answers every connection the mock realm accepts, until the listener
    /// closes or accepting one fails.
    fn serve_connections(listener: TcpListener, realm_id: [u8; 32], public_key: Vec<u8>, seen: Arc<Mutex<Vec<String>>>) {
        for mut stream in listener.incoming().map_while(Result::ok) {
            serve_connection(&mut stream, &realm_id, &public_key, &seen);
        }
    }

    /// Reads one request and writes its answer.
    fn serve_connection(stream: &mut std::net::TcpStream, realm_id: &[u8; 32], public_key: &[u8], seen: &Arc<Mutex<Vec<String>>>) {
        let Some(request) = read_request(stream) else {
            return;
        };
        let (status, body) = handle(&request, realm_id, public_key, seen);
        let reply =
            format!("HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
        let _ = stream.write_all(reply.as_bytes());
    }

    struct Request {
        method: String,
        path: String,
        body: String,
    }

    fn read_request(stream: &mut std::net::TcpStream) -> Option<Request> {
        let buf = read_until_complete(stream)?;
        let headers_end = find(&buf, b"\r\n\r\n")?;
        let headers = String::from_utf8_lossy(&buf[..headers_end]).to_string();
        let mut lines = headers.lines();
        let first = lines.next()?;
        let mut parts = first.split_whitespace();
        let method = parts.next()?.to_string();
        let path = parts.next()?.to_string();
        let body = String::from_utf8_lossy(&buf[headers_end + 4..]).to_string();
        Some(Request { method, path, body })
    }

    /// Reads until the buffered bytes hold a whole request: its headers and
    /// the body their content-length announces.
    fn read_until_complete(stream: &mut std::net::TcpStream) -> Option<Vec<u8>> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        while read_chunk(stream, &mut buf, &mut chunk)? && !request_complete(&buf) {}
        Some(buf)
    }

    /// Appends the bytes one read returns to `buf`; false once the peer has
    /// closed, so nothing more is coming.
    fn read_chunk(stream: &mut std::net::TcpStream, buf: &mut Vec<u8>, chunk: &mut [u8]) -> Option<bool> {
        let n = stream.read(chunk).ok()?;
        buf.extend_from_slice(&chunk[..n]);
        Some(n > 0)
    }

    /// Whether `buf` holds the headers and the body their content-length
    /// announces.
    fn request_complete(buf: &[u8]) -> bool {
        let Some(headers_end) = find(buf, b"\r\n\r\n") else {
            return false;
        };
        let headers = String::from_utf8_lossy(&buf[..headers_end]).to_string();
        let length = headers
            .lines()
            .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").and_then(|v| v.trim().parse::<usize>().ok()))
            .unwrap_or(0);
        buf.len() >= headers_end + 4 + length
    }

    fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
        hay.windows(needle.len()).position(|w| w == needle)
    }

    fn handle(request: &Request, realm_id: &[u8; 32], public_key: &[u8], seen: &Arc<Mutex<Vec<String>>>) -> (String, String) {
        if request.method == "POST" && request.path == "/api/v1/join/sessions" {
            handle_create(request, realm_id, public_key, seen)
        } else if request.method == "GET" && request.path.starts_with("/api/v1/join/sessions/") {
            handle_poll(seen)
        } else {
            ("404 Not Found".into(), r#"{"error":"not found"}"#.into())
        }
    }

    /// Verifies a create request's proof exactly as the realm does.
    fn handle_create(request: &Request, realm_id: &[u8; 32], public_key: &[u8], seen: &Arc<Mutex<Vec<String>>>) -> (String, String) {
        let Ok(body) = serde_json::from_str::<Json>(&request.body) else {
            return ("400 Bad Request".into(), r#"{"error":"bad json"}"#.into());
        };
        let Some(proof_json) = body.get("proof") else {
            return ("400 Bad Request".into(), r#"{"error":"missing_proof"}"#.into());
        };
        let mut request_body = body.clone();
        if let Some(map) = request_body.as_object_mut() {
            map.remove("proof");
        }
        let Ok(message_request) = proof::canonical_json(&request_body) else {
            return ("400 Bad Request".into(), r#"{"error":"bad_request"}"#.into());
        };
        let Ok(proof) = proof_from_json(proof_json) else {
            return ("400 Bad Request".into(), r#"{"error":"bad_proof"}"#.into());
        };
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
        if let Err(reason) = proof::verify_device_request(public_key, realm_id, JOIN_SESSION_PROCEDURE, &message_request, &proof, now) {
            return ("400 Bad Request".into(), format!(r#"{{"error":"{reason}"}}"#));
        }
        seen.lock().map(|mut s| s.push("create-verified".into())).ok();
        ("201 Created".into(), r#"{"session_id":"s-1","join_url":"https://realm.example/join/s-1","expires_at":"+10m"}"#.into())
    }

    /// Answers a poll: pending the first time, confirmed after.
    fn handle_poll(seen: &Arc<Mutex<Vec<String>>>) -> (String, String) {
        match record_poll(seen) {
            Some(0) => ("200 OK".into(), r#"{"status":"pending","expires_at":"+10m"}"#.into()),
            _ => (
                "200 OK".into(),
                concat!(
                    r#"{"status":"confirmed","org_identity":"mri:org:io.macula/rgfaber","#,
                    r#""cert_pem":"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n","#,
                    r#""citizen_did":"0011","ucan":"eyJhbGciOiJFUzI1NiJ9.eyJleHAiOjE3OTIwMDAwMDB9.sig"}"#
                )
                .into(),
            ),
        }
    }

    /// Records this poll in the mock's log and reports how many earlier polls
    /// were still pending.
    fn record_poll(seen: &Arc<Mutex<Vec<String>>>) -> Option<usize> {
        let mut log = seen.lock().ok()?;
        let pending = log.iter().filter(|m| m.as_str() == "pending").count();
        log.push(if pending == 0 { "pending".into() } else { "confirmed".into() });
        Some(pending)
    }

    fn proof_from_json(value: &Json) -> Result<DeviceRequestProof, String> {
        let nonce: [u8; 16] = hex::decode(value.get("nonce").and_then(Json::as_str).ok_or("nonce")?)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "nonce size".to_string())?;
        Ok(DeviceRequestProof {
            timestamp_ms: value.get("timestamp").and_then(Json::as_u64).ok_or("timestamp")?,
            nonce,
            signature: hex::decode(value.get("signature").and_then(Json::as_str).ok_or("signature")?).map_err(|e| e.to_string())?,
        })
    }

    #[test]
    fn a_join_session_runs_from_link_to_stored_credential() {
        let dir = tempfile::tempdir().expect("temp dir");
        let id = identity(dir.path());
        let (base, seen) = mock_realm("io.macula", id.carried_key());
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);

        // The mock verifies the proof exactly as the realm does: a request
        // whose signed bytes it cannot rebuild is refused, so this passing
        // is the red-first check of the whole citizen path.
        let created = create_session("io.macula", &base, &id, now).expect("create");
        assert_eq!(created.session_id, "s-1");
        assert!(created.join_url.starts_with("https://realm."), "a link the person can open");
        assert_eq!(seen.lock().expect("lock").first().map(String::as_str), Some("create-verified"));

        match poll_session(&base, &created.session_id).expect("poll") {
            SessionStatus::Pending { .. } => {}
            other => panic!("first poll must be pending, got {other:?}"),
        }
        let confirmed = match poll_session(&base, &created.session_id).expect("poll") {
            SessionStatus::Confirmed(c) => c,
            other => panic!("second poll must be confirmed, got {other:?}"),
        };
        let cred = credential_from_confirmed(&id, "io.macula", &base, confirmed, now);
        assert_eq!(cred.tier, crate::realm::Tier::Citizen);
        assert_eq!(cred.handle().as_deref(), Some("rgfaber"));
        assert_eq!(cred.ucan_expires_ms(), Some(1_792_000_000_000));
        let path = crate::realm::store_credential_in(dir.path(), &cred).expect("store");
        assert!(path.exists());
        assert_eq!(crate::realm::load_credential_in(dir.path(), id.node_id(), "io.macula"), Some(cred));
    }

    #[test]
    fn a_session_changed_on_the_way_is_refused_by_the_realm() {
        // The mock signs nothing; instead, prove that the request the realm
        // rebuilds is the request the proof covered by moving a field after
        // signing (a relay's edit).
        let dir = tempfile::tempdir().expect("temp dir");
        let id = identity(dir.path());
        let body = join_request_body(&id);
        let signed = proof::canonical_json(&body).expect("canonical");
        let proof = id.device_request_proof(&crate::realm::realm_id_of("io.macula"), JOIN_SESSION_PROCEDURE, &signed, 1_000).expect("proof");
        let mut tampered = signed.clone();
        if let macula_rust::cbor::Value::Map(pairs) = &mut tampered {
            pairs[0] = (macula_rust::cbor::Value::text("public_key"), macula_rust::cbor::Value::text("someone-elses-key"));
        }
        assert!(
            proof::verify_device_request(
                &id.carried_key(),
                &crate::realm::realm_id_of("io.macula"),
                JOIN_SESSION_PROCEDURE,
                &tampered,
                &proof,
                1_000
            )
            .is_err(),
            "a body edit breaks the proof"
        );
        assert!(
            proof::verify_device_request(&id.carried_key(), &crate::realm::realm_id_of("io.macula"), JOIN_SESSION_PROCEDURE, &signed, &proof, 1_000)
                .is_ok()
        );
    }

    /// Raf's citizen flow, live: the realm's controller renders a confirmed
    /// session as {status, org_identity, cert_pem, citizen_did, ucan} — no
    /// refresh_token, no oauth_account. This is that exact body.
    #[test]
    fn rafs_citizen_confirmation_is_accepted_and_stored() {
        let dir = tempfile::tempdir().expect("temp dir");
        let id = identity(dir.path());
        let body = concat!(
            r#"{"status":"confirmed","org_identity":"mri:org:io.macula/rgfaber","#,
            r#""cert_pem":"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n","#,
            r#""citizen_did":"0011","ucan":"eyJhbGciOiJFUzI1NiJ9.eyJleHAiOjE3OTIwMDAwMDB9.sig"}"#
        );
        let status = parse_session_status(200, body);
        let SessionStatus::Confirmed(confirmed) = status else {
            panic!("a real confirmed body must parse as Confirmed, got {status:?}");
        };
        assert_eq!(confirmed.org_identity, "mri:org:io.macula/rgfaber");
        assert_eq!(confirmed.refresh_token, "", "the realm sends none on this path");
        assert!(confirmed.account.is_none(), "and no oauth account");
        assert!(confirmed.cert_pem.is_some() && confirmed.citizen_did.is_some() && confirmed.ucan.is_some());

        let cred = credential_from_confirmed(&id, "io.macula", "https://realm.macula.io", confirmed, 1_000);
        assert_eq!(cred.tier, crate::realm::Tier::Citizen);
        assert_eq!(cred.handle().as_deref(), Some("rgfaber"), "the handle comes from org_identity");
        assert_eq!(cred.ucan_expires_ms(), Some(1_792_000_000_000));
        let path = crate::realm::store_credential_in(dir.path(), &cred).expect("store");
        assert!(path.exists());
        assert_eq!(crate::realm::load_credential_in(dir.path(), id.node_id(), "io.macula"), Some(cred));
    }

    #[test]
    fn session_replies_shape_like_the_realm_documents() {
        assert_eq!(parse_session_status(410, "{}"), SessionStatus::Expired);
        assert_eq!(parse_session_status(200, r#"{"status":"pending","expires_at":"x"}"#), SessionStatus::Pending { expires_at: "x".into() });
        assert!(matches!(parse_session_status(500, "{}"), SessionStatus::Error(_)));
        assert!(parse_created(403, r#"{"error":"no"}"#).is_err());
        assert_eq!(realm_base_url("io.macula"), "https://realm.macula.io", "the realm's own URL formula");
    }
}
