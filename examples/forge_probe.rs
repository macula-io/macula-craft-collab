//! Forged-publisher probe: connects to one station and publishes a Cursor
//! message that CLAIMS another node's author id — the envelope carries this
//! process's identity, the payload names the victim. A peer with the
//! verified-publisher check must drop it: the victim's cursor keeps its real
//! name and the forged one never appears.
//!
//! Usage: forge_probe <host> <port> <station_node_hex> <realm_hex> <doc> <victim_node_hex> [forged_name]

use std::time::{Duration, Instant};

use craft_collab::{Kind, Message, Transport};
use macula_craft_collab::{Identity, MeshConfig, MeshTransport, Roster, Share};

fn arg(i: usize) -> String {
    std::env::args().nth(i).unwrap_or_else(|| {
        eprintln!("usage: forge_probe <host> <port> <node_hex> <realm_hex> <doc> <victim_hex> [forged_name]");
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
    let realm = hex32(&arg(4));
    let doc = arg(5);
    let victim = arg(6);
    let forged_name = std::env::args().nth(7).unwrap_or_else(|| "HACKED".into());

    let cfg = MeshConfig {
        host,
        port,
        station_node_id: station,
        realm_id: realm,
        realm_key: Vec::new(),
        realm_name: "io.macula".into(),
        share: Share::default(),
        // This probe is its own share's host: it serves the key distributor,
        // and the record of who may pull is its own.
        membership: None,
        removed: None,
    };
    let identity = match Identity::load_or_create("pq_hybrid", "forge-probe", "Forger") {
        Ok(identity) => identity,
        Err(e) => {
            eprintln!("identity failed: {e}");
            std::process::exit(1);
        }
    };
    let checks = Roster::new(identity.node_id()).expect("the probe's admission record").checks();
    let cfg = MeshConfig { membership: Some(checks.membership), removed: Some(checks.removed), ..cfg };
    let mut mesh = match MeshTransport::connect(&cfg, &identity) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("connect failed: {e}");
            std::process::exit(1);
        }
    };
    let forger = mesh.author().to_string();
    println!("forger: connected as {}", &forger[..8.min(forger.len())]);

    // `self` makes the claim honest (the payload author IS the envelope's):
    // a relay check — the cursor must arrive under `forged_name`.
    let victim = if victim == "self" { forger.clone() } else { victim };

    // The claim: the payload's author is the victim, the envelope's is us.
    let msg = Message {
        doc,
        author: victim.clone(),
        epoch: 1,
        seq: 1,
        sent_at_ms: 0,
        kind: Kind::CursorMoved { position: None, name: Some(forged_name.clone()) },
    };
    match mesh.send(msg) {
        Ok(()) => println!("forged-cursor-sent victim={} name={forged_name}", &victim[..8.min(victim.len())]),
        Err(e) => {
            eprintln!("send failed: {e}");
            std::process::exit(1);
        }
    }

    // Stay connected briefly so the publication reaches the station.
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
    }
    println!("done");
}
