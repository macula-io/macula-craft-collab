# Changelog

All notable changes to this crate are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the crate is pre-1.0,
so a minor version may carry a small breaking change where one was the right
call.

## [0.9.0] - 2026-10-30

Builds on macula-craft-seam 0.7.0 (released the same day).

### Added

- **A person is told when an edit of theirs did not leave** (macula-craft-collab#39).
  `MeshTransport::refused_publications()` — and through it the seam's
  `Transport::refused_publications()`, so the session an app holds reports it as
  `refused_publications()` and `stats()["unsent"]` — now adds up every way this
  crate knows a publication did not go out:

  1. **the mesh refused it** before anything was sent (the share could not seal
     it, or no link would take it). Nothing is ever sent in the clear instead,
     so this is counted in `publish_sealed` and never a message that became
     readable;
  2. **the transport could not even queue it**: `send` was asked after the mesh
     thread had ended, or the message would not serialise. The seam ignores
     `send`'s answer, so this is counted at the source or not at all;
  3. **the pool accepted it and could not deliver it**
     (`Pool::unsent_publications`, macula-rust 0.14.1): sent on a link that
     ended before the station was known to have read it, and then not sent
     again in time — no link came up before subscribers would have refused it,
     the pool closed, or too many were already waiting.

  What is **not** counted: a publication the station took and answered for that
  no subscriber then read. The wire acknowledges no PUBLISH, so neither this
  crate nor the pool can name that case.

### Fixed

- **An edit made while the path to the station loses every packet is no longer
  lost when that link ends** (macula-craft-collab#38, macula-rust#57): macula-rust
  0.14.1 sends such a publication again on the next link. When it cannot, the
  pool counts it (`Pool::unsent_publications`) and this release carries that
  count to the app, so the person hears about it instead of the edit vanishing.

### Changed

- **macula-craft-seam 0.6 -> 0.7.0.** The seam's order buffer reports what it
  is holding (`order: {held, gaps, stalled}` in `stats()`), recovers a stall
  past its deadline through the snapshot path, and a snapshot that bypasses the
  buffer now occupies its sequence position instead of opening a hole
  (rgfaber/craft-libs#2). No API of this crate changed; `stats()` gains the
  two keys.

## [0.8.0] - 2026-10-28

A shared document is readable only by its holders (macula-craft-collab#26).
The threat model and the acceptance list it was built against are on the issue.
A sealed share is readable by the people the host invited **and by the host
itself**; what that does not mean, and the bounds on revocation, are collected
under "Limits in this release" below.

### Breaking

- **A sealed share can no longer be shared with a realm.** A hosting config with
  `share_realm` or `share_role` is refused with a message naming the limit
  (threat model decision 5), where it used to admit any realm member presenting
  a live membership. Their grants renew from their own membership while the
  credential that pulls a share's key is minted once per invite line and never
  renewed, and those two lifetimes cannot be reconciled in this release. A
  sealed share goes to named people, one invite each; `share_verifier` stays in
  the crate for the release that models a realm share's key.
- **A sealed share must name its distributor.** `MeshTransport::connect` refuses
  a joiner's `Share` with no `distributor`, instead of letting macula-rust's
  member side auto-pin the first answer that arrives (threat model T5).

### Changed

- **Every message a share carries is sealed.** A share is a group: the prefix
  `<realm>/~<host>/craft/<share>`, where the share id is random and minted per
  session and never derived from the document id, and the seven topics hang
  under it as `<prefix>/<name>_v1`. The host mints the prefix when it starts
  sharing; a joiner is given it by its invite (macula-craft-seam 0.6, invite
  v5) together with the credential that pulls its key. There is no clear arm
  left: a publication that cannot be sealed is refused and counted
  (`refused_publications`), and an event that arrives clear under the prefix is
  refused and counted (`clear_refused`), so a policy regression would show
  instead of leaking.
- **The host serves the share's key distributor.** `<~host>/group_keys_v1`
  (macula-rust 0.14's `Distributor`), sealed and grant-gated, pinned by the
  invite to the host's node id. Its admission answers come from `Roster` — the
  grants, revocations and invites the host itself minted — so an invitee can
  pull the key before it knocks, a revoked holder is refused every epoch, and a
  grant newer than the revocation admits again. The host's own key comes from
  the same distributor, pulled like anyone else's.
- **The invitee's key credential outlives every grant it can meet.** It is
  minted at the UCAN ceiling (`GROUP_CREDENTIAL_MS`, ten years less a minute),
  not at the invite's own life: the grant it must outlast is minted when the
  host **approves** the join, a pending joiner has no expiry in the seam, and a
  yes can come days later — with five minutes of clock tolerance on top. It is
  presented on every key pull, so a credential that died with a ten-minute
  invite would cut a live holder off the key while its grant, and the document,
  went on working. Its job is only that: what admits a pull is `Roster`, never
  the credential's expiry, and a share's prefix is random per session, so an old
  credential names a share that no longer exists and pulls nothing. Held down by
  a live test with a two-second invite. The rotation itself is not proven live:
  this crate serves its distributor at macula-rust's default interval and never
  asks for a shorter one (macula-craft-collab#28), so the two-second test is the
  same property at the layer available — not an observed rotation, and this
  release does not claim one.
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
- **The host is in the reader set.** It wrote the document and serves its key.
  Sealed here means readable by the holders and by the host's own node — not by
  the realm, not by the stations, and not by a revoked holder past the bounds
  below.
- **Revocation cannot unread what was read.** A revoked holder keeps everything
  it already opened, and can still open events sealed under any epoch it already
  holds until that epoch's accept time — at most 90 minutes after its removal.
  New edits stop reaching it much sooner, in about 20 minutes.
- **A share is retried, not healed, while its distributor is away.** A share
  whose key cannot be had waits (`no_distributor`) and every publication in the
  meantime is refused and counted; nothing is sent in the clear. A line from an
  ended session waits the same way — the wait itself is not bounded yet
  (macula-craft-collab#31).

### Added

- **`refused_publications()` and `unusable()`**, so no refusal is silent in
  either direction: a message this node could not publish is counted (the seam's
  `send` is fire-and-forget and cannot see it), and an event that opened but
  carried no message is counted instead of dropped.
- `tests/share.rs`: a share end to end against macula-go's in-process stations
  (built by `scripts/build-teststation.sh`, which CI now runs): the host, an
  invited joiner, an edit each way, a realm member reading ciphertext only, a
  revoked holder refused the key and its own edit opened but not applied, a
  revoked holder still refused across a host transport restart with a re-invite
  admitted, a share pinned to another node waiting rather than joining, a share
  with no pin refused, a publication that cannot be sealed counted, and a short
  invite whose credential still pulls after it lapses.

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
