# Path Quilt Distributed Scientific Method

Status: **experimental local protocol prototype**. It coordinates evidence; it
does not execute untrusted workloads, decide truth, mint PQC, or publish data.

Each experiment begins with a canonical public manifest containing a title,
testable hypothesis, protocol hash, dataset hash, metric, falsification rule and
licence. The experiment ID is the SHA-256 digest of that manifest. A deterministic
plan divides the experiment into bounded units and assigns two to seven replica
slots per unit.

Each replica is submitted by a distinct 64-hex Peer ID. Results are represented
by content hash and size, not by a popularity vote. Two independently submitted
matching hashes mark a unit `reproduced`. When all replica slots are filled but
no two hashes match, the unit becomes `conflict`; contradictory evidence remains
visible. Everything else is `pending`. These states describe reproducibility,
not scientific truth.

The prototype stores atomic, mode-0600 state locally and rejects symlinked,
oversized or foreign task input. It has no network publishing command. A future
PQVPN transport must add authenticated hybrid signatures, validator admission,
timeouts, blinded assignment, dataset-authorisation proofs and public Asgard
publication consent before this can become a distributed service.

```bash
tools/pq-research-method.py --state ./lab propose \
  --title "Experiment" --hypothesis "X changes Y" \
  --protocol protocol.txt --dataset-hash 64_HEX \
  --metric "absolute error" --falsification "error >= 1" \
  --licence CC-BY-4.0

tools/pq-research-method.py --state ./lab plan \
  --experiment EXPERIMENT_ID --units 10 --replicas 3
```

`submit` records one result file per task and independent peer; `evaluate`
creates a content-addressable report suitable for later signing and publication.
