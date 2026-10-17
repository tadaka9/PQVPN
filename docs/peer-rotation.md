# Health-aware peer rotation

`tools/pqvpn-peer-rotation.py` creates an atomic client profile from a trusted
topology. Discovery order and exit selection rotate independently. A node must
be explicitly assigned the `exit` role before it can carry internet traffic;
a bootstrap is never promoted automatically.

The supplied workstation topology keeps `AEwarness` as Helsinki bootstrap,
`Awarness` as Stockholm exit, and the local computer as a loopback-only relay
candidate. This preserves the existing no-egress policy on Helsinki and does
not expose the workstation to the WAN. Add the `exit` role to another node only
after its egress policy, firewall, abuse controls and operator consent are in
place.

Run a safe preview:

```bash
python3 tools/pqvpn-peer-rotation.py \
  --topology "$HOME/Documents/PQVPN-rotation/topology.json" \
  --base "$HOME/Documents/PQVPN-rotation/base-client.json" \
  --output "$HOME/Documents/PQVPN-rotation/active-client.json" \
  --state "$HOME/Documents/PQVPN-rotation/state.json" \
  --dry-run
```

Remove `--dry-run` to update `active-client.json`. The output and state are
written with mode `0600`, under an exclusive lock, and replaced atomically.
If no declared exit or discovery peer is healthy, generation fails closed and
the previous active profile remains untouched.

For multiple authorized exits, `capacity_weight` (0.1–100, default 1) controls
how many **new sessions** each node receives. Allocation is weighted-fair,
health-gated and uses probe latency only as a tie-breaker. The atomic state file
keeps bounded assignment counters. Existing sessions retain flow affinity:
PQVPN never stripes packets across exits, avoiding TCP reordering and identity
changes mid-session. Probes run locally and persist only health and latency;
there is no central telemetry collector.

```json
{"name":"exit-large","roles":["relay","exit"],"capacity_weight":2.0}
```
