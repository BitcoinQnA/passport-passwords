#!/bin/bash
# Keyless rendezvous for when the Prime is plugged into the laptop.
# The box is not reachable on the tailnet; both sides dial Jarvis outbound.
# Jarvis only forwards opaque bytes (ql-byte-splice.py, bound to its Tailscale IP).
# The laptop never listens.
#
# Start the splice (one-off, not a service):
#   ssh jarvis 'python3 -u /tmp/ql-byte-splice.py 100.80.55.66 19876'
# Path check (no USB, no Prime prompt):
#   on the box:  passwords-ql-bridge --relay "$RELAY" dial-test
#   on the laptop: ql-usb-relay.exe --dial-only --connect 100.80.55.66:19876
# To carry a session later, after Owen OKs a Prime prompt:
#   on the laptop: ql-usb-relay.exe --connect 100.80.55.66:19876
#   on the box:    passwords-ql-bridge --state "$STATE" --relay "$RELAY" serve
set -euo pipefail
RELAY='ssh -o BatchMode=yes -o ConnectTimeout=30 -o ServerAliveInterval=15 jarvis@100.80.55.66 -W 100.80.55.66:19876'
STATE=${STATE:-/home/box/.config/passwords-ql/grok-bot.state}
BRIDGE=/workspace/prime-ql-autofill/passport-passwords/host-bridge/target/release/passwords-ql-bridge
exec "$BRIDGE" --state "$STATE" --relay "$RELAY" "$@"
