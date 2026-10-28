//! The host's admission record for its share: who may pull the share group's
//! key. The group key is what makes a document readable, so the distributor
//! this host serves asks this record before it answers a pull
//! (`macula-rust`'s `MembershipCheck` and `RemovedCheck`, wired into the
//! transport by `MeshConfig`).
//!
//! What the record holds is the host's own decisions, as it made them: the
//! grants it minted (each with the lifetime its holder was granted), the
//! revocations it signed, and the invites it minted (a person who has an
//! invite must pull the key *before* it knocks, so an invitee is a reader
//! from the moment its invite is live — threat model §4). It is written from
//! the issuing side and read from the serving side, in one process.
//!
//! Two answers, and the second is absolute:
//!
//! - **removed**: revoked, and no grant newer than the revocation. A newer
//!   grant is the host re-inviting that person, and re-admits them.
//! - **membership**: the host itself, or a live holder, or the invitee of a
//!   live invite — and never anyone the record has removed.
//!
//! The record dies with the session, and so does the share prefix it guards:
//! a session restart mints a new random share id, so yesterday's invitations
//! name a prefix nothing serves any more (threat model §4).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use macula_rust::group::{Membership, MembershipCheck, MembershipFuture, RemovedCheck, org_of};

use crate::hex_bytes;

/// What the host knows about one node, as it decided it.
#[derive(Clone, Default)]
struct Entry {
    /// When the newest grant for this node was minted.
    granted_ms: Option<u64>,
    /// When that grant stops being live.
    grant_ends_ms: Option<u64>,
    /// When this node's newest invite stops being live.
    invited_until_ms: Option<u64>,
    /// When the host last revoked this node.
    revoked_at_ms: Option<u64>,
}

impl Entry {
    /// Whether the host's revocation is the last word: revoked, and nothing
    /// newer granted since.
    fn removed(&self) -> bool {
        match self.revoked_at_ms {
            None => false,
            Some(at) => self.granted_ms.is_none_or(|granted| granted <= at),
        }
    }

    /// Whether this node may hold the share's key at `now`: a live grant, or
    /// a live invite.
    fn live(&self, now_ms: u64) -> bool {
        let grant = self.grant_ends_ms.is_some_and(|ends| ends > now_ms);
        let invited = self.invited_until_ms.is_some_and(|until| until > now_ms);
        grant || invited
    }
}

/// The host's admission record for one share: the org it serves (this node's
/// own namespace, `~<node id>`), the node itself, and what it decided about
/// every other node it has invited.
pub struct Roster {
    /// The org this record answers for: `~<host>`, the second segment of the
    /// share's prefix.
    org: String,
    /// The host's own node id: it may always pull its own share's key.
    host: [u8; 32],
    entries: Mutex<BTreeMap<[u8; 32], Entry>>,
}

impl Roster {
    /// A record for the org `~host_hex`, kept by `host_hex` itself.
    pub fn new(host_hex: &str) -> Result<Arc<Roster>, String> {
        let host = hex_bytes(host_hex)?;
        let host: [u8; 32] = host.try_into().map_err(|_| "a node id is 32 bytes".to_string())?;
        Ok(Arc::new(Roster { org: format!("~{host_hex}"), host, entries: Mutex::new(BTreeMap::new()) }))
    }

    /// The record's answers, as the mesh asks them.
    pub fn checks(self: &Arc<Self>) -> Checks {
        let membership = Arc::clone(self);
        let removed = Arc::clone(self);
        Checks {
            membership: Arc::new(move |prefix: String, caller: [u8; 32]| -> MembershipFuture { answer(Arc::clone(&membership), prefix, caller) }),
            removed: Arc::new(move |prefix: &str, caller: [u8; 32]| -> bool { removed.removed(prefix, caller) }),
        }
    }

    /// A grant the host minted for `holder`, live from `issued_ms` to
    /// `ends_ms`. The newest grant is the host's last word, as it is for the
    /// seam's own table: an older one never outlives its replacement.
    pub fn note_grant(&self, holder: &str, issued_ms: u64, ends_ms: u64) {
        let Some(node) = node_of(holder) else { return };
        let mut entries = self.lock();
        let entry = entries.entry(node).or_default();
        if entry.granted_ms.is_none_or(|at| issued_ms >= at) {
            entry.granted_ms = Some(issued_ms);
            entry.grant_ends_ms = Some(ends_ms);
        }
    }

    /// A revocation the host signed for `holder` at `issued_ms`.
    pub fn note_revocation(&self, holder: &str, issued_ms: u64) {
        self.note(holder, |entry| {
            entry.revoked_at_ms = Some(entry.revoked_at_ms.map_or(issued_ms, |at| at.max(issued_ms)));
        });
    }

    /// An invite the host minted for `invitee`, live until `until_ms`.
    pub fn note_invite(&self, invitee: &str, until_ms: u64) {
        self.note(invitee, |entry| {
            entry.invited_until_ms = Some(entry.invited_until_ms.map_or(until_ms, |until| until.max(until_ms)));
        });
    }

    /// Whether `caller` may pull the key of a group under `prefix`, at
    /// `now_ms`.
    pub fn membership(&self, prefix: &str, caller: [u8; 32], now_ms: u64) -> Membership {
        if !self.owns(prefix) {
            return Membership::NotAMember;
        }
        let Some(entry) = self.lock().get(&caller).cloned() else {
            // The host itself, and nobody else the record is silent about.
            return match caller == self.host {
                true => Membership::In,
                false => Membership::NotAMember,
            };
        };
        match entry.removed() || !entry.live(now_ms) {
            true => Membership::NotAMember,
            false => Membership::In,
        }
    }

    /// Whether the host has removed `caller` from `prefix`'s group for good:
    /// revoked, with no grant newer than the revocation.
    pub fn removed(&self, prefix: &str, caller: [u8; 32]) -> bool {
        match self.owns(prefix) {
            true => self.lock().get(&caller).is_some_and(Entry::removed),
            // Another org's group is not this record's to admit: refused
            // rather than answered from this share's roster.
            false => true,
        }
    }

    /// Whether `prefix` names a group of this record's org: `~<host>` is the
    /// prefix's second segment, which is what a distributor here answers for.
    fn owns(&self, prefix: &str) -> bool {
        org_of(prefix).is_ok_and(|org| org == self.org)
    }

    fn note(&self, node: &str, what: impl FnOnce(&mut Entry)) {
        let Some(node) = node_of(node) else { return };
        what(self.lock().entry(node).or_default());
    }

    fn lock(&self) -> MutexGuard<'_, BTreeMap<[u8; 32], Entry>> {
        self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// A node id written as hex, as bytes.
fn node_of(hex: &str) -> Option<[u8; 32]> {
    let raw = hex_bytes(hex).ok()?;
    <[u8; 32]>::try_from(raw).ok()
}

impl std::fmt::Debug for Roster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Roster").field("org", &self.org).field("nodes", &self.lock().len()).finish()
    }
}

/// A roster's two answers, as [`crate::MeshConfig`] carries them: closures,
/// so the transport never names the record's type.
#[derive(Clone)]
pub struct Checks {
    pub membership: MembershipCheck,
    pub removed: RemovedCheck,
}

impl std::fmt::Debug for Checks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Checks")
    }
}

/// One membership answer, computed here so the closure the mesh calls is a
/// single expression.
fn answer(roster: Arc<Roster>, prefix: String, caller: [u8; 32]) -> MembershipFuture {
    let answer = roster.membership(&prefix, caller, craft_collab::now_ms());
    Box::pin(async move { answer })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "aa";
    const NOW: u64 = 1_000_000;

    fn roster() -> Arc<Roster> {
        Roster::new(&HOST.repeat(32)).expect("a roster")
    }

    fn prefix() -> String {
        format!("io.macula/~{}/craft/0123456789abcdef0123456789abcdef", HOST.repeat(32))
    }

    fn node(fill: u8) -> [u8; 32] {
        [fill; 32]
    }

    fn node_hex(fill: u8) -> String {
        node(fill).iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The host is the org: its own share's key is its own, whoever else the
    /// record knows about.
    #[test]
    fn the_host_always_may_pull_its_own_shares_key() {
        let roster = roster();
        assert_eq!(roster.membership(&prefix(), node(0xaa), NOW), Membership::In);
        assert_eq!(roster.membership(&prefix(), node(0xbb), NOW), Membership::NotAMember, "a stranger is not a holder");
        assert!(!roster.removed(&prefix(), node(0xbb)), "and has not been removed: it was never here");
    }

    /// Another org's group is not this record's to admit.
    #[test]
    fn another_orgs_group_is_refused_rather_than_answered() {
        let roster = roster();
        let foreign = format!("io.macula/~{}/craft/0123456789abcdef0123456789abcdef", "bb".repeat(32));
        assert_eq!(roster.membership(&foreign, node(0xaa), NOW), Membership::NotAMember);
        assert!(roster.removed(&foreign, node(0xaa)), "refused, never admitted from this share's roster");
        assert_eq!(roster.membership("not-a-group", node(0xaa), NOW), Membership::NotAMember);
    }

    /// The key pull comes before the knock, so an invitee is a reader from the
    /// moment its invite is live — and not one minute after it lapses.
    #[test]
    fn an_invitee_is_a_reader_while_its_invite_is_live() {
        let roster = roster();
        roster.note_invite(&node_hex(0xbb), NOW + 60_000);
        assert_eq!(roster.membership(&prefix(), node(0xbb), NOW), Membership::In);
        assert_eq!(roster.membership(&prefix(), node(0xbb), NOW + 60_000), Membership::NotAMember, "lapsed");
    }

    /// A holder's grant is its membership, and it ends when the grant does.
    #[test]
    fn a_grant_is_a_membership_until_it_ends() {
        let roster = roster();
        roster.note_grant(&node_hex(0xbb), NOW, NOW + 60_000);
        assert_eq!(roster.membership(&prefix(), node(0xbb), NOW + 59_999), Membership::In);
        assert_eq!(roster.membership(&prefix(), node(0xbb), NOW + 60_000), Membership::NotAMember);
        assert!(!roster.removed(&prefix(), node(0xbb)));
    }

    /// Revoked is absolute — until the host mints a newer grant, which is its
    /// yes to that person again.
    #[test]
    fn a_revocation_is_the_last_word_until_a_newer_grant() {
        let roster = roster();
        roster.note_grant(&node_hex(0xbb), NOW, NOW + 600_000);
        roster.note_revocation(&node_hex(0xbb), NOW + 10_000);
        assert!(roster.removed(&prefix(), node(0xbb)), "revoked, and nothing newer");
        assert_eq!(roster.membership(&prefix(), node(0xbb), NOW + 11_000), Membership::NotAMember, "a live grant does not outrank the revocation");

        roster.note_grant(&node_hex(0xbb), NOW + 20_000, NOW + 620_000);
        assert!(!roster.removed(&prefix(), node(0xbb)), "a newer grant is the host's yes");
        assert_eq!(roster.membership(&prefix(), node(0xbb), NOW + 21_000), Membership::In);
    }

    /// A grant minted in the same millisecond as the revocation is not newer
    /// than it: the seam's rule, kept here.
    #[test]
    fn a_grant_no_newer_than_the_revocation_does_not_readmit() {
        let roster = roster();
        roster.note_revocation(&node_hex(0xbb), NOW);
        roster.note_grant(&node_hex(0xbb), NOW, NOW + 60_000);
        assert!(roster.removed(&prefix(), node(0xbb)));
        assert_eq!(roster.membership(&prefix(), node(0xbb), NOW + 1), Membership::NotAMember);
    }

    /// The newest grant is the one that counts: a shorter one the host mints
    /// later replaces the longer one it minted before, as it does for the
    /// seam's own table.
    #[test]
    fn the_newest_grant_is_the_one_that_counts() {
        let roster = roster();
        roster.note_grant(&node_hex(0xbb), NOW, NOW + 600_000);
        roster.note_grant(&node_hex(0xbb), NOW + 1, NOW + 60_000);
        assert_eq!(roster.membership(&prefix(), node(0xbb), NOW + 500_000), Membership::NotAMember);
        roster.note_grant(&node_hex(0xbb), NOW + 2, NOW + 900_000);
        assert_eq!(roster.membership(&prefix(), node(0xbb), NOW + 500_000), Membership::In);
    }
}
