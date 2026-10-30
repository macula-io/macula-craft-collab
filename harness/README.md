# The sweep harness

A live sweep creates identities and realm memberships, and it must end every
membership it created (macula-craft-collab#35). This directory is the half that
guarantees it, whichever way the sweep ends.

## `run.sh`

Runs a driver against **one** realm and tears the run down on both paths.

    MACULA_SWEEP_REALM=net.beam-campus \
    MACULA_STATIONS=<host:port:node_hex,...> \
    MACULA_SWEEP_CONTROLS=8791:<key file>,8792:<key file> \
    harness/run.sh -- <driver command>

- `MACULA_SWEEP_REALM` is required and `io.macula` is refused outright: the
  realm is named once, and nothing may default to production
  (macula-craft-collab#41).
- The same name is exported as `MACULA_CRAFT_AUTOJOIN_REALM`, so the app's
  silent auto-join targets the sweep's realm and not a realm of its own
  choosing.
- `MACULA_CRAFT_RESIGN_ON_SHUTDOWN=1` is set: an instance that exits on its own
  resigns before its transport closes.
- After the driver exits, on **either** path, `teardown.py` resigns every
  listed instance. A teardown failure fails the sweep even when the driver
  passed, and the exit code says which happened.

## `teardown.py`

Reaches each instance over its control port — the one transport that reaches
the process holding the identity key, which is the only key a resignation may
be signed with — and calls `collab.realmResign`.

The per-app half, which each craft app implements in its own repository:

| | |
|---|---|
| method | `collab.realmResign`, no params |
| reply | `{"ok": true, "result": {"all_ended": true, "outcomes": [...]}}` |

`all_ended` is the crate's own answer, `ResignReport::all_ended()`: true only
when the realm was read back and said that every membership this node held has
**ended**. A record that merely landed is not that — the realm's answer is the
proof, not the record's echo (macula-realm#167).

## What a red run means

The sweep cannot be green before the realm serves the membership read
(macula-realm#167) and before the resignation listener resolves a record's
realm instead of trusting the name in it (macula-realm#169): until both land, a
resignation publishes but nothing ends, and every run is red **by design**.
That is the honest state, and it is why the teardown is checked rather than
assumed.
