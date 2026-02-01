#!/bin/sh
# Helper script to create a TUN device and bring it up for PQVPN
# Edit DEVICE/CIDR/ROUTE_VIA as needed before running, or pass through sudo

# Defaults (edit if you want other values)
DEVICE="pqvpn0"
CIDR="10.10.10.2/24"     # change to the IP you want on the client side
ROUTE_VIA=""             # optional gateway IP for default route; leave empty to skip replacing system default

set -e

echo "Creating TUN device $DEVICE (idempotent)"
# Try to add tuntap; ignore error if exists
ip tuntap add dev "$DEVICE" mode tun 2>/dev/null || true

if [ -n "$CIDR" ]; then
  echo "Assigning IP $CIDR to $DEVICE"
  ip addr add "$CIDR" dev "$DEVICE" 2>/dev/null || ip addr replace "$CIDR" dev "$DEVICE" || true
fi

echo "Bringing $DEVICE up"
ip link set dev "$DEVICE" up 2>/dev/null || true

if [ -n "$ROUTE_VIA" ]; then
  echo "Setting default route via $ROUTE_VIA dev $DEVICE"
  ip route replace default via "$ROUTE_VIA" dev "$DEVICE" || true
else
  echo "apply_routes requested but no ROUTE_VIA provided: skipping automatic default route replacement (safe default)"
  echo "# To force default replace, set ROUTE_VIA to a gateway IP or uncomment the following line"
  echo "# ip route replace default dev $DEVICE || true"
fi

echo "TUN setup complete."

echo "Current interface info:"
ip -brief addr show dev "$DEVICE" || true
ip route show | sed -n '1,200p'
