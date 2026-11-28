#!/bin/bash
# Keyless rendezvous for when the Prime is plugged into a laptop that can reach
# a splice host outbound. Both sides dial that host; the laptop never listens.
# The splice (ql-byte-splice.py) forwards opaque bytes, bound to a Tailscale IP.
#
# Start the splice (one-off, not a service):
#   ssh splice-host 'python3 -u ql-byte-splice.py <splice-tailscale-ip> 19876'
# Path check (no USB, no Prime prompt):
#   passwords-ql-bridge --relay "$RELAY" dial-test
#   ql-usb-relay --dial-only --connect <splice-tailscale-ip>:19876
# To carry a session, after the Prime prompt is approved:
#   ql-usb-relay --connect <splice-tailscale-ip>:19876
#   passwords-ql-bridge --state "$STATE" --relay "$RELAY" serve
set -euo pipefail
RELAY=${RELAY:?set RELAY to an ssh or connect command that reaches the USB helper}
STATE=${STATE:-ql-host.state}
BRIDGE=${BRIDGE:-passwords-ql-bridge}
exec "$BRIDGE" --state "$STATE" --relay "$RELAY" "$@"
