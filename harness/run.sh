#!/usr/bin/env bash
# Runs one live sweep against ONE realm and ends every membership it created.
#
# The sweep's halves (macula-craft-collab#35): the driver does the work, and
# this wrapper is what guarantees the teardown — on the success path and on
# the failure path, which is the half a driver's own `finally` cannot promise
# for the instances it started and then lost.
#
# The realm is named once, here, and exported to the app as BOTH the realm it
# signs in to and the realm it auto-joins. Naming them separately is how a
# sweep came to join io.macula while being pointed somewhere else
# (macula-craft-collab#41): this script refuses to run without
# MACULA_SWEEP_REALM rather than letting anything default to production.
#
# Usage:
#   MACULA_SWEEP_REALM=net.beam-campus \
#   MACULA_STATIONS=host:port:node_hex[,...] \
#   MACULA_SWEEP_CONTROLS=8791:/path/control-key.8791,8792:/path/control-key.8792 \
#   harness/run.sh -- <the app's driver command...>
#
# MACULA_SWEEP_CONTROLS lists every instance the driver starts, as
# `<control port>:<key file>`. The teardown asks each of them to resign; an
# instance that cannot be reached is a failed sweep, because a membership
# nobody ended is exactly the row this exists to prevent.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

: "${MACULA_SWEEP_REALM:?MACULA_SWEEP_REALM must name the realm this sweep runs against (e.g. net.beam-campus)}"
: "${MACULA_SWEEP_CONTROLS:?MACULA_SWEEP_CONTROLS must list '<port>:<key file>' per instance the driver starts}"

if [ "$MACULA_SWEEP_REALM" = "io.macula" ]; then
  echo "sweep: refusing to run against io.macula, the production realm" >&2
  exit 2
fi

# One realm, two variables: a driver that reads either gets the same answer,
# and neither can fall back to a production default.
export MACULA_CRAFT_AUTOJOIN_REALM="$MACULA_SWEEP_REALM"
export MACULA_SWEEP_REALM
export MACULA_CRAFT_RESIGN_ON_SHUTDOWN=1

if [ "${1:-}" = "--" ]; then
  shift
fi
if [ "$#" -eq 0 ]; then
  echo "sweep: nothing to run (pass the driver command after --)" >&2
  exit 2
fi

sweep_status=0
"$@" || sweep_status=$?

teardown_status=0
python3 "$HERE/teardown.py" --controls "$MACULA_SWEEP_CONTROLS" || teardown_status=$?

if [ "$teardown_status" -ne 0 ]; then
  echo "sweep: the teardown did not end every membership (driver exit $sweep_status) — this run leaves rows behind" >&2
  exit 3
fi
if [ "$sweep_status" -ne 0 ]; then
  echo "sweep: the driver failed (exit $sweep_status); every membership it created has ended" >&2
  exit "$sweep_status"
fi
echo "sweep: clean, every membership it created has ended"
