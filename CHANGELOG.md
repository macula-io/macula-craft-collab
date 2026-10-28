# Changelog

All notable changes to this crate are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the crate is pre-1.0,
so a minor version may carry a small breaking change where one was the right
call.

## [Unreleased]

A shared document is readable only by its holders (macula-craft-collab#26).
Not released: the threat model is on the issue, and 0.8.0 is cut once the
acceptance list is met.

### Changed

- **Every message a share carries is sealed.** A share is a group: the prefix
  `<realm>/~<host>/craft/<share>`, where the share id is random and minted per
  session and never derived from the document id, and the seven topics hang
  under it as `<prefix>/<name>_v1`. The host mints the prefix when it starts
  sharing; a joiner is given it by its invite (macula-craft-seam 0.6, invite
  v5) together with the credential that pulls its key. There is no clear arm
  left: a publication not under the group is refused, and an event that arrives
  clear under it is refused and counted (`clear_refused`), so a policy
  regression would show instead of leaking.
- **The host serves the share's key distributor.** `<~host>/group_keys_v1`
  (macula-rust 0.14's `Distributor`), sealed and grant-gated, pinned by the
  invite to the host's node id. Its admission answers come from `Roster` — the
  grants, revocations and invites the host itself minted — so an invitee can
  pull the key before it knocks, a revoked holder is refused every epoch, and a
  grant newer than the revocation admits again. The host's own key comes from
  the same distributor, pulled like anyone else's.
- **The invitee's key credential outlives a short invite.** It is minted for a
  day (`GROUP_CREDENTIAL_MS`, the seam's grant ceiling) **plus the invite's own
  life**, because the grant it must outlast is minted at the knock, and the
  knock may come at the last second the invite is live. It is presented on every
  key pull and epochs rotate every fifteen minutes, so a credential that died
  with a ten-minute invite would cut a live holder off the key while its grant,
  and the document, went on working. What refuses a pull is `Roster`, never the
  credential's expiry: a lapsed invite with no grant minted since is still
  refused. Held down by a live test with a two-second invite; the rotation
  itself is not proven live, because macula-rust 0.14 cannot shorten the
  interval from the member side (macula-io/macula-rust#52), so this release
  says the two-second test is the same property at the layer available, not that
  a rotation was observed.
- **A share that cannot have its key waits, visibly, and fails closed.**
  `MeshTransport::waiting()` names what a share is waiting for — `no_distributor`
  while the distributor is not answering, and `not_a_member` or
  `membership_unknown` when a pull is refused mid-session — and the transport
  retries; a refusal that is about one message rather than the share fails the
  connect, because waiting would never end. Publications are refused
  throughout (`unopened()`, `last_unopened()` and `clear_refused()` count what
  a share saw and could not use).
- **macula-rust 0.14 and macula-craft-seam 0.6**, released crates only, no
  `[patch]` and no path override.
- `--collab <config.json>` is the hosting instance: its `join` flag is refused
  rather than honoured, because a share id is minted per session and an
  instance that should rejoin does so through a fresh invite line.

### Limits in this release

- **One shared document per instance.** Its group prefix is minted for it and it
  serves that share's distributor; two shares of one host would need one pool and
  one distributor serving several groups, which this transport does not do yet
  (macula-craft-collab#27). The limit fails closed: a share whose key cannot be had
  waits (`no_distributor`) and never publishes in the clear, and a group under
  another org is refused by the distributor rather than served.

### Added

- `tests/share.rs`: a share end to end against macula-go's in-process stations
  (built by `scripts/build-teststation.sh`, which CI now runs): the host, an
  invited joiner, an edit each way, a realm member reading ciphertext only, a
  revoked holder refused the key and its own edit opened but not applied, and a
  share pinned to another node waiting rather than joining.

## [0.7.0] - 2026-10-20

The release for the wire 1.0 fleet.

### Changed

- **macula-rust 0.11.0**, the wire 1.0 final (was 0.9). The node speaks the
  version 5 handshake only, so it reaches stations on wire 1.0 and no others;
  a station still on the earlier wire refuses it at the handshake rather than
  midway through a session. Two station acknowledgements change what this
  crate can rely on: a subscription now returns once the station has accepted
  it (macula-rust#33), so `MeshTransport::connect` makes its seven
  subscriptions as barriers and a refused or unanswered one fails the connect
  with an error instead of handing back a transport that hears nothing; and
  serving waits for its own acknowledgement (macula-rust#35), which this crate
  does not use. A subscription dropped without unsubscribing no longer
  withdraws a later one of its topic (macula-rust#34), so a subscription made
  right after one was dropped still stands.
- **macula-craft-seam 0.5.5** (was 0.5.2): a revocation verifies at any later
  time, a revoke survives the host restarting, and a per-person invite minted
  after a revoke is the host's yes. The seam's `Transport` trait is unchanged,
  so the adapter needed no change for it.
- **A publication's payload is clear or sealed, never a bare value**
  (`frame::Payload`, macula-rust 0.11). Document messages are published
  `Payload::Clear`, and an inbound event is read only when it is clear: a
  sealed group event under the same topic name is someone else's traffic and
  carries no document message, so it is not counted as one.

## [0.6.0] - 2026-10-17

### Changed

- Realm memberships renew about every 10 minutes while a transport runs, for
  a person's and a device's alike, and the fresh token is handed to the shared
  session (macula-realm#46).

## [0.5.0] - 2026-10-14

### Changed

- On macula-craft-seam 0.5: named text bodies, ordered id lists and undo
  steps.

## [0.4.1] - 2026-10-14

### Fixed

- Realm HTTPS on rustls 0.23: minreq 3, with aws-lc-rs installed as the
  process crypto provider (macula-craft-collab#11).

## [0.4.0] - 2026-10-14

### Changed

- On macula-craft-seam 0.4.0.

## [0.3.0] - 2026-10-14

### Changed

- On macula-craft-seam 0.3.0.

## [0.2.0] - 2026-10-14

### Changed

- On macula-craft-seam 0.2.0.

## [0.1.0] - 2026-10-14

First release: the `Transport` over macula-rust, identity, grants and realm
membership.
