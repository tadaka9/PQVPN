# PQC wallet and exchange boundary

The PQVPN GUI exposes the installation's existing self-custody wallet. Its Ed25519 and ML-DSA-87 private keys remain in the private local wallet file; the GUI requests only public status from `pqvpn_node --wallet-info`.

The creator badge is an address match against the public creator registry in source control. It is not inferred from a name and grants no network, minting, or peer-administration privilege.

## What is real now

- a unique local hybrid wallet identity;
- a public address that can be copied without revealing keys;
- a short deterministic audible fingerprint and matching note sequence derived
  from that public address, generated and played locally on explicit request;
- deterministic creator-address verification;
- a local scenario lens for ownership share, profit/loss direction, and annual staking projection;
- validation rules for short-lived `PQC/EUR` exchange quotes.

## What deliberately remains unavailable

Balances are not shown as real until genesis and ledger finality are deployed. The scenario lens uses only values entered locally and is not market data, financial advice, or a yield promise. Exchange execution stays disabled until an identified venue, authenticated quote transport, signature verification, expiry checking, explicit confirmation, settlement, and applicable compliance boundaries are implemented and independently reviewed.

The interface therefore never creates invented fills, an invented PQC price, hidden spread, or a false staking return.

The audible fingerprint is not a digital signature, collision-resistant proof
or replacement for address comparison. It is a bounded human cue. The public
wallet document and its Ed25519 + ML-DSA-87 verification remain authoritative;
PQVPN does not transmit the melody, microphone data or an audio-derived ID.
