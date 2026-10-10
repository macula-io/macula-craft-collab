//! Live device-tier join probe: connects to one station as a fresh identity,
//! proves the key to the realm's membership procedure and prints what the
//! realm answered (never the UCAN itself — it is a credential).
//!
//! Usage: device_join_probe <host> <port> <station_node_hex> <realm_name> <realm_key_hex> [slug]

use std::time::Duration;

use macula_craft_collab::{Identity, realm};
use macula_rust::pool::{Opts, Pool, Seed};

fn arg(i: usize) -> String {
    std::env::args().nth(i).unwrap_or_else(|| {
        eprintln!("usage: device_join_probe <host> <port> <node_hex> <realm_name> [slug]");
        std::process::exit(2);
    })
}

fn hex32(s: &str) -> [u8; 32] {
    let v: Vec<u8> = (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or(0)).collect();
    v.try_into().unwrap_or([0; 32])
}

fn main() {
    let host = arg(1);
    let port: u16 = arg(2).parse().unwrap_or(4433);
    let station = hex32(&arg(3));
    let realm_name = arg(4);
    let realm_key_hex = arg(5);
    let realm_key: Vec<u8> = (0..realm_key_hex.len()).step_by(2).map(|i| u8::from_str_radix(&realm_key_hex[i..i + 2], 16).unwrap_or(0)).collect();
    let slug = std::env::args().nth(6).unwrap_or_else(|| "device-probe".into());

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("runtime");
    rt.block_on(async move {
        let dir = macula_craft_collab::identity::craft_identity_dir().unwrap_or_else(|| std::env::temp_dir().join("craft-device-probe"));
        let identity =
            Identity::load_or_create_with(macula_rust::profile::Profile::PqHybrid, &slug, "Device Probe", None, Some(&dir)).expect("identity");
        let mut opts = Opts::new(identity.key());
        // Calls resolve procedure advertisements under the realm's pinned
        // key — the same public trust anchor macula-mcp pins; pubsub needs none.
        opts.realm_trust.insert(realm::realm_id_of(&realm_name), realm_key.clone());
        let pool = Pool::connect(vec![Seed { host, port, node_id: station }], opts).await.expect("connect");
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
        match realm::join_device(&pool, &identity, &realm_name, now).await {
            Ok(cred) => {
                println!("tier: {:?}", cred.tier);
                println!("org: {}", cred.org_identity);
                println!("citizen_did: {}...", &cred.node_id[..8.min(cred.node_id.len())]);
                println!("ucan: {} bytes, expires {:?}", cred.ucan.as_deref().map(str::len).unwrap_or(0), cred.ucan_expires_ms());
                match realm::store_credential(&cred) {
                    Ok(path) => println!("stored: {}", path.display()),
                    Err(e) => println!("store failed: {e}"),
                }
                // The host-side check, against the realm's own key: the live
                // UCAN must verify for THIS node and no one else.
                let now_s = (now / 1_000) as i64;
                match realm::verify_membership(cred.ucan.as_deref().unwrap_or(""), &realm_key, &realm_name, &cred.node_id, now_s) {
                    Ok(()) => println!("membership verifies at the realm's key for this node"),
                    Err(e) => println!("membership verify failed: {e}"),
                }
                // The refresh leg: a device membership re-mints (a fresh
                // proof; a citizen one would be returned untouched).
                let before = cred.ucan_expires_ms();
                // The realm's TTL resolves to whole seconds; wait one out so
                // the renewal's own expiry is visibly later.
                std::thread::sleep(Duration::from_secs(2));
                let now = now + 2_000;
                match realm::renew_membership(&pool, &identity, &realm_name, now).await {
                    Ok(fresh) => println!("renewed: {} -> {:?}", before.map(|e| e.to_string()).unwrap_or_default(), fresh.ucan_expires_ms()),
                    Err(e) => println!("renew failed: {e}"),
                }
            }
            Err(e) => {
                println!("join failed: {e}");
                std::process::exit(1);
            }
        }
        pool.close().await;
        std::thread::sleep(Duration::from_millis(200));
    });
}
