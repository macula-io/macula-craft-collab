#!/usr/bin/env python3
"""Ends every membership a sweep created, through each app's control port.

The control port is the one transport that reaches the process holding the
identity key, and the resignation must be signed with that key
(macula-craft-collab#35): a second process reading the same key would be a
second holder of the member's identity, not a teardown.

The contract this script relies on, which is each app's half:

  method  `collab.realmResign`, no params.
  reply   `{"ok": true, "result": {"all_ended": true, "outcomes": [...]}}`

`all_ended` is the crate's own answer (`ResignReport::all_ended`): true only
when the realm was read back and answered that every membership this node held
has ENDED. A record that merely landed is `false` here — the realm's answer is
the proof, not the record's echo (macula-realm#167).

An instance that cannot be reached, refuses the key, or answers anything but
`ok` with `all_ended` true, fails the teardown: a membership nobody ended is
the row this exists to prevent.
"""

import argparse
import json
import socket
import sys


def call(port, key, method, timeout):
    """One request, one reply, on the control port's JSON-lines protocol."""
    request = json.dumps({"id": 1, "key": key, "method": method, "params": {}}) + "\n"
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as conn:
        conn.sendall(request.encode())
        reader = conn.makefile("r", encoding="utf-8")
        line = reader.readline()
    if not line:
        return {"ok": False, "error": "the control port closed without an answer"}
    return json.loads(line)


def resign(port, key_file, method, timeout):
    """The resign call against one instance; returns (ok, why)."""
    try:
        with open(key_file, encoding="utf-8") as handle:
            key = handle.read().strip()
    except OSError as e:
        return False, f"no control key at {key_file}: {e}"
    try:
        reply = call(port, key, method, timeout)
    except (OSError, json.JSONDecodeError) as e:
        return False, f"port {port}: {e}"
    if not reply.get("ok"):
        return False, f"port {port} refused: {reply.get('error')}"
    result = reply.get("result") or {}
    if result.get("all_ended") is not True:
        return False, f"port {port} did not end every membership: {json.dumps(result)}"
    return True, f"port {port}: {len(result.get('outcomes') or [])} membership(s) ended"


def main():
    parser = argparse.ArgumentParser(description="Resign every membership a sweep created.")
    parser.add_argument("--controls", required=True, help="'<port>:<key file>' per instance, comma separated")
    parser.add_argument("--method", default="collab.realmResign")
    parser.add_argument("--timeout", type=float, default=120.0, help="seconds per instance")
    args = parser.parse_args()

    entries = [entry for entry in args.controls.split(",") if entry.strip()]
    if not entries:
        print("teardown: no control endpoints given: nothing could be ended", file=sys.stderr)
        return 1

    failed = 0
    for entry in entries:
        port_text, _, key_file = entry.strip().partition(":")
        try:
            port = int(port_text)
        except ValueError:
            print(f"teardown: {entry!r} is not '<port>:<key file>'", file=sys.stderr)
            failed += 1
            continue
        ok, why = resign(port, key_file, args.method, args.timeout)
        stream = sys.stdout if ok else sys.stderr
        print(f"teardown: {'ended' if ok else 'FAILED'} {why}", file=stream)
        failed += 0 if ok else 1

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
