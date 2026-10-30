# macula-craft-collab

Co-edit one document with people on other machines, over the
[Macula](https://macula.io) mesh, with no server holding the document.

This crate is the Macula side of the
[macula-craft-seam](https://crates.io/crates/macula-craft-seam) collaboration
seam: it implements the seam's `Transport` over
[macula-rust](https://crates.io/crates/macula-rust), and supplies what the
seam leaves to an adapter.

It tracks the released crates only: macula-rust 0.14 and macula-craft-seam 0.7.
A node on this crate reaches stations on wire 1.0 and no others.

- **Identity**: one persistent signing key per person per device (OS secure
  store, file fallback). The node id is derived from it; every message is
  signed, and a message whose author is not its verified publisher is dropped.
- **Grants**: the host signs per-document grants, revocations and invite tokens
  (`IdentityIssuer`); every peer verifies them (`verified_access`).
- **A shared document travels sealed**: every message is published under the
  share's group — `<realm>/~<host>/craft/<share>`, the share id random and new
  per session — and sealed under that group's current epoch key. A realm member
  without the grant, and every station relaying it, sees ciphertext and the
  facts a topic and an envelope carry, never the document. There is no clear
  path in this crate: a publication that is not under the group is refused
  rather than sent in the open.
- **The host distributes the group's key**: it serves `<~host>/group_keys_v1`
  in its own namespace, sealed and grant-gated (`Roster`, which answers who may
  pull from the grants, revocations and invites the host minted), and answers a
  pull before a person knocks, because a joiner must hold the key to publish
  its join request. A revoked holder is refused every epoch; a grant minted
  after the revocation is the host's yes again.
- **Realm membership**: device-tier join, the realm sign-in session, and
  `RealmMemberVerifier`, which admits members of a realm by their
  membership UCAN (issued by the realm's key, audience = the presenting node).
  While a transport runs, it renews this node's membership of its realm
  (a person's or a device's) about every 10 minutes, ahead of the realm's
  1 hour token, and hands the fresh token to the shared session, so a
  member admitted to a document stays in while they remain a member
  (macula-realm#46). Only the transport's own realm is renewed: calls
  resolve under its pinned key alone.
- **Cross-realm**: `RealmTrust`, the realms a person trusts by key, added from
  a realm's `/.well-known/macula-realm.json` under the name they mean and the
  fingerprint they checked. A host in one realm can share a document with
  another realm's members.
- **Ending a membership**: `MeshTransport::resign_memberships()` publishes one
  signed `0x21` record per realm this node holds a membership of — the realm's
  name, this node's `member_did`, and the moment — then reads every one of them
  back (`POST /api/v1/memberships/status`, proof over
  `macula_realm.read_realm_membership`) and reports `Ended` only when the realm
  says the row **ended**. A record that merely landed is not an answer
  (macula-craft-collab#35, macula-realm#167). `MACULA_CRAFT_RESIGN_ON_SHUTDOWN=1` makes a transport do
  it when it stops, which is what a test sweep sets and a person's app never
  does; `harness/run.sh` runs a sweep and tears it down on both paths.

## When the key cannot be had

A share fails closed: nothing is ever sent in the clear. If the share's key
distributor is not answering, `MeshTransport::connect` still returns, with
`waiting()` naming `no_distributor`, and the transport retries until it does;
every publication meanwhile is refused, and an application shows that waiting
state instead of pretending the document is shared. Any other refusal — the
distributor saying `not_a_member`, say — fails the connect outright, because
waiting would never end.

## One share per instance

An instance shares one document: its group prefix is minted for it, and it
serves that share's distributor. Sharing two documents at once needs one pool
and one distributor serving several groups (macula-craft-collab#27).

## Topics

Every topic is the share's prefix and one name, so five segments in all:

- `<prefix>/text_edited_v1`: document text updates
- `<prefix>/cursor_moved_v1`: cursor presence
- `<prefix>/document_shared_v1`: join snapshot request and response
- `<prefix>/command_applied_v1`: replayed commands
- `<prefix>/join_requested_v1`: a person asking to be let in
- `<prefix>/grant_issued_v1`: the host's grant
- `<prefix>/holder_revoked_v1`: the host's revocation

The document id, author and payload are in the message, never in the topic.

## Tests

`cargo test` runs the unit tests and, in `tests/share.rs`, a share end to end
against macula-go's in-process stations: a host, an invited joiner, an edit
each way, a revoked holder, and a realm member who reads ciphertext only. The
stations are built first:

```sh
./scripts/build-teststation.sh   # needs Go; writes target/teststation
cargo test
```

## Examples

`examples/` holds live probes (pub/sub, device join, sign-in, a forged
publisher). Each takes the station and realm as arguments.

Licensed under Apache-2.0.
