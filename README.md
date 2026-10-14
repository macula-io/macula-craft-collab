# macula-craft-collab

Co-edit one document with people on other machines, over the
[Macula](https://macula.io) mesh, with no server holding the document.

This crate is the Macula side of the
[macula-craft-seam](https://crates.io/crates/macula-craft-seam) collaboration
seam: it implements the seam's `Transport` over
[macula-rust](https://crates.io/crates/macula-rust), and supplies what the
seam leaves to an adapter.

- **Identity**: one persistent signing key per person per device (OS secure
  store, file fallback). The node id is derived from it; every message is
  signed, and a message whose author is not its verified publisher is dropped.
- **Grants**: the host signs per-document grants, revocations and invite tokens
  (`IdentityIssuer`); every peer verifies them (`verified_access`).
- **Realm membership**: device-tier join and renewal, the realm sign-in session,
  and `RealmMemberVerifier`, which admits members of a realm by their
  membership UCAN (issued by the realm's key, audience = the presenting node).
- **Cross-realm**: `RealmTrust`, the realms a person trusts by key, added from
  a realm's `/.well-known/macula-realm.json` under the name they mean and the
  fingerprint they checked. A host in one realm can share a document with
  another realm's members.

## Topics

- `craft/collab/text_edited_v1`: document text updates
- `craft/collab/cursor_moved_v1`: cursor presence
- `craft/collab/document_shared_v1`: join snapshot request and response

The document id, author and payload are in the message, never in the topic.

## Examples

`examples/` holds live probes (pub/sub, device join, sign-in, a forged
publisher). Each takes the station and realm as arguments.

Licensed under Apache-2.0.
