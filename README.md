# macula-craft-collab

The Macula mesh transport for the shared Craft collaboration seam
([`craft-collab`](https://github.com/storytold/craft-libs)): implements the
seam's `Transport` trait over `macula-rust`, so a Craft app's document text
edits, cursor presence and join snapshots travel between peers as signed
publications in a mesh realm, with no central server.

Local spike repo; no GitHub repository yet. Built on released crates only
(`macula-rust` from crates.io).

## Topics

- `craft/collab/text_edited_v1` — document text updates
- `craft/collab/cursor_moved_v1` — cursor presence
- `craft/collab/document_shared_v1` — join snapshot request/response

The document id, author and payload live in the message, not the topic.
