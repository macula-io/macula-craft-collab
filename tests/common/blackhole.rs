//! A node's path to its station that can lose every packet and still be a
//! path: the node keeps talking to a relay that forwards datagrams both ways,
//! and while it is closed nothing crosses but nothing is refused either.
//!
//! This is deliberately not [`super::lab::Lab::drop_node`]. That closes the
//! node's connection at the station, so macula-rust redials and replays, and
//! the node recovers by reconnecting. The probe in macula-io/macula-craft-collab#36
//! loses the *packets*: the connection lives for the whole gap (QUIC's idle
//! timeout is 300 s), no link ends, no replay runs, and so nothing above the
//! transport is ever told there was a gap. That is the case an edit made
//! offline is lost in.
//!
//! The counters are the point of it: they say whether an edit that vanished
//! ever left the node. A datagram counted in `to_station` while `dropping` is
//! an edit the node did send; an edit the node never sent shows as no datagram
//! at all.

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

/// How long a socket read waits before checking whether it should stop.
const POLL: Duration = Duration::from_millis(50);

/// A UDP relay in front of a station, closable on demand.
pub struct BlackHole {
    addr: SocketAddr,
    station: SocketAddr,
    dropping: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    to_station: Arc<AtomicU64>,
    from_station: Arc<AtomicU64>,
    held_to_station: Arc<AtomicU64>,
    held_from_station: Arc<AtomicU64>,
    threads: Vec<thread::JoinHandle<()>>,
}

impl BlackHole {
    /// A relay that forwards to `station` and listens for the node.
    pub fn in_front_of(station: SocketAddr) -> BlackHole {
        let front = Arc::new(bind_loopback());
        let up = Arc::new(bind_loopback());
        let addr = front.local_addr().expect("the relay's front socket");
        let dropping = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let to_station = Arc::new(AtomicU64::new(0));
        let from_station = Arc::new(AtomicU64::new(0));
        let held_to_station = Arc::new(AtomicU64::new(0));
        let held_from_station = Arc::new(AtomicU64::new(0));

        // The node's address, learnt from what it sends: one node dials
        // through one relay here.
        let node_addr: Arc<std::sync::Mutex<Option<SocketAddr>>> =
            Arc::new(std::sync::Mutex::new(None));

        let forward = {
            let (dropping, stop) = (Arc::clone(&dropping), Arc::clone(&stop));
            let (to_station, held) = (Arc::clone(&to_station), Arc::clone(&held_to_station));
            let (front, up) = (Arc::clone(&front), Arc::clone(&up));
            let node_addr = Arc::clone(&node_addr);
            thread::spawn(move || {
                loop {
                    let Some((datagram, from)) = receive(&front) else {
                        if stop.load(Ordering::Relaxed) {
                            break;
                        }
                        continue;
                    };
                    *node_addr.lock().expect("the node address") = Some(from);
                    if dropping.load(Ordering::Relaxed) {
                        held.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    if up.send_to(&datagram, station).is_ok() {
                        to_station.fetch_add(1, Ordering::Relaxed);
                    }
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                }
            })
        };

        let back = {
            let (dropping, stop) = (Arc::clone(&dropping), Arc::clone(&stop));
            let (from_station, held) = (Arc::clone(&from_station), Arc::clone(&held_from_station));
            let (front, up) = (Arc::clone(&front), Arc::clone(&up));
            thread::spawn(move || {
                loop {
                    let Some((datagram, _)) = receive(&up) else {
                        if stop.load(Ordering::Relaxed) {
                            break;
                        }
                        continue;
                    };
                    if dropping.load(Ordering::Relaxed) {
                        held.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    let node = *node_addr.lock().expect("the node address");
                    if let Some(node) = node {
                        if front.send_to(&datagram, node).is_ok() {
                            from_station.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                }
            })
        };

        BlackHole {
            addr,
            station,
            dropping,
            stop,
            to_station,
            from_station,
            held_to_station,
            held_from_station,
            threads: vec![forward, back],
        }
    }

    /// Where the node dials: the station's node id, this relay's address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The station this relay forwards to.
    pub fn station(&self) -> SocketAddr {
        self.station
    }

    /// From now on, every datagram in either direction is dropped.
    pub fn close(&self) {
        self.dropping.store(true, Ordering::Relaxed);
    }

    /// From now on, datagrams cross again.
    pub fn open(&self) {
        self.dropping.store(false, Ordering::Relaxed);
    }

    /// Whether the relay is dropping right now.
    pub fn dropping(&self) -> bool {
        self.dropping.load(Ordering::Relaxed)
    }

    /// Datagrams that crossed node -> station.
    pub fn to_station(&self) -> u64 {
        self.to_station.load(Ordering::Relaxed)
    }

    /// Datagrams that crossed station -> node.
    pub fn from_station(&self) -> u64 {
        self.from_station.load(Ordering::Relaxed)
    }

    /// Datagrams the node sent while the relay was dropping: the edits it did
    /// send, and the proof that it was trying.
    pub fn held_to_station(&self) -> u64 {
        self.held_to_station.load(Ordering::Relaxed)
    }

    /// Datagrams the station sent while the relay was dropping.
    pub fn held_from_station(&self) -> u64 {
        self.held_from_station.load(Ordering::Relaxed)
    }
}

impl Drop for BlackHole {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

/// A loopback UDP socket whose reads time out, so its thread can be stopped.
fn bind_loopback() -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("a loopback UDP socket");
    socket.set_read_timeout(Some(POLL)).expect("a read timeout");
    socket
}

/// One datagram, or `None` when the read timed out and the caller should
/// check whether it is still wanted.
fn receive(socket: &UdpSocket) -> Option<(Vec<u8>, SocketAddr)> {
    let mut buffer = vec![0_u8; 65_536];
    match socket.recv_from(&mut buffer) {
        Ok((len, from)) => {
            buffer.truncate(len);
            Some((buffer, from))
        }
        Err(_) => None,
    }
}
