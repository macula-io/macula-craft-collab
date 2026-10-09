//! Smoke probe: connects to one fleet station and exchanges one message,
//! printing whatever it hears for a while. For validating a station, the
//! realm and cross-station pubsub before a demo.
//!
//! Usage: pubsub_probe <host> <port> <station_node_hex> <realm_hex> <label> <listen|send|both>

use std::time::{Duration, Instant};

use craft_collab::{Kind, Message, Transport};
use macula_craft_collab::{MeshConfig, MeshTransport};

fn arg(i: usize) -> String {
    std::env::args().nth(i).unwrap_or_else(|| {
        eprintln!(
            "usage: pubsub_probe <host> <port> <node_hex> <realm_hex> <label> <listen|send|both>"
        );
        std::process::exit(2);
    })
}

fn hex32(s: &str) -> [u8; 32] {
    let v: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or(0))
        .collect();
    v.try_into().unwrap_or([0; 32])
}

fn main() {
    let host = arg(1);
    let port: u16 = arg(2).parse().unwrap_or(4433);
    let station = hex32(&arg(3));
    let realm = hex32(&arg(4));
    let label = arg(5);
    let mode = arg(6);

    let cfg = MeshConfig {
        host,
        port,
        station_node_id: station,
        realm_id: realm,
        realm_key: Vec::new(),
        profile: "pq_hybrid".into(),
    };
    let mut mesh = match MeshTransport::connect(&cfg) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{label}: connect failed: {e}");
            std::process::exit(1);
        }
    };
    let author = mesh.author();
    println!("{label}: connected as {}", &author[..8]);

    if mode == "send" || mode == "both" {
        let msg = Message {
            doc: "probe".into(),
            author: author.clone(),
            seq: 1,
            sent_at_ms: 0,
            kind: Kind::CursorMoved {
                position: Some(format!("hello from {label}")),
                name: Some(label.clone()),
            },
        };
        match mesh.send(msg) {
            Ok(()) => println!("{label}: sent"),
            Err(e) => println!("{label}: send failed: {e}"),
        }
    }

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut heard = 0;
    while Instant::now() < deadline {
        for m in mesh.poll() {
            if m.author != author {
                heard += 1;
                println!("{label}: HEARD from {}: {:?}", &m.author[..8], m.kind);
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    println!("{label}: done, heard {heard} from others");
}
