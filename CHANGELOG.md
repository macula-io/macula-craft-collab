# Changelog

All notable changes to this crate are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the crate is pre-1.0,
so a minor version may carry a small breaking change where one was the right
call.

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
