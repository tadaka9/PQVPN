"""
Tests for pqvpn.zkp module.
"""

import os

import pytest

from pqvpn.zkp import (
    FiatShamirZKP,
    SchnorrZKP,
    authenticate_with_zkp,
    create_zkp_prover,
)


class TestSchnorrZKP:
    def test_prove_and_verify(self):
        zkp = SchnorrZKP()
        secret = b"my_secret_key_32_bytes!!!!!!!"
        challenge = b"challenge_data"

        proof = zkp.prove_knowledge(secret, challenge)
        assert len(proof) == 64  # 32 + 32

        result = zkp.verify_proof(proof, secret, challenge)
        assert result == True

    def test_verify_wrong_secret(self):
        zkp = SchnorrZKP()
        secret = b"my_secret_key_32_bytes!!!!!!!"
        wrong_secret = b"wrong_secret_32_bytes!!!!!!!"
        challenge = b"challenge_data"

        proof = zkp.prove_knowledge(secret, challenge)
        result = zkp.verify_proof(proof, wrong_secret, challenge)
        assert result == False

    def test_verify_wrong_challenge(self):
        zkp = SchnorrZKP()
        secret = b"my_secret_key_32_bytes!!!!!!!"
        challenge = b"challenge_data"
        wrong_challenge = b"wrong_challenge"

        proof = zkp.prove_knowledge(secret, challenge)
        result = zkp.verify_proof(proof, secret, wrong_challenge)
        assert result == False


class TestFiatShamirZKP:
    def test_prove_and_verify(self):
        base_zkp = SchnorrZKP()
        zkp = FiatShamirZKP(base_zkp)
        secret = b"my_secret_key_32_bytes!!!!!!!"
        challenge = b"challenge_data"

        proof = zkp.prove_knowledge(secret, challenge)
        assert len(proof) > 32  # commitment + base proof

        result = zkp.verify_proof(proof, secret, challenge)
        assert result == True

    def test_verify_wrong_secret(self):
        base_zkp = SchnorrZKP()
        zkp = FiatShamirZKP(base_zkp)
        secret = b"my_secret_key_32_bytes!!!!!!!"
        wrong_secret = b"wrong_secret_32_bytes!!!!!!!"
        challenge = b"challenge_data"

        proof = zkp.prove_knowledge(secret, challenge)
        result = zkp.verify_proof(proof, wrong_secret, challenge)
        assert result == False


class TestCreateZKPProver:
    def test_create_schnorr(self):
        zkp = create_zkp_prover("schnorr")
        assert isinstance(zkp, SchnorrZKP)

    def test_create_fiat_shamir(self):
        zkp = create_zkp_prover("fiat-shamir")
        assert isinstance(zkp, FiatShamirZKP)

    def test_create_invalid(self):
        with pytest.raises(ValueError):
            create_zkp_prover("invalid")


class TestAuthenticateWithZKP:
    def test_authenticate_success(self):
        secret = b"my_secret_key_32_bytes!!!!!!!"
        public = secret  # Simplified for test
        challenge = b"challenge_data"

        result = authenticate_with_zkp(secret, public, challenge, "schnorr")
        assert result == True

    def test_authenticate_failure(self):
        secret = b"my_secret_key_32_bytes!!!!!!!"
        wrong_public = b"wrong_secret_32_bytes!!!!!!!"
        challenge = b"challenge_data"

        result = authenticate_with_zkp(secret, wrong_public, challenge, "schnorr")
        assert result == False


class TestBandwidthRangeZKP:
    def test_commit_and_prove_range(self):
        from pqvpn.zkp import BandwidthRangeZKP
        zkp = BandwidthRangeZKP()
        value = 500  # bandwidth usage
        limit = 1000
        randomness = os.urandom(32)

        # Create commitment
        commitment = zkp.commit_value(value, randomness)

        # Prove range [0, limit]
        proof = zkp.prove_range(value, 0, limit, randomness)

        # Verify
        assert zkp.verify_range(proof, commitment)
        assert proof.range_min == 0
        assert proof.range_max == limit

    def test_verify_invalid_range(self):
        from pqvpn.zkp import BandwidthRangeZKP
        zkp = BandwidthRangeZKP()
        value = 1500  # Over limit
        limit = 1000
        randomness = os.urandom(32)

        # Should fail to prove
        with pytest.raises(ValueError):
            zkp.prove_range(value, 0, limit, randomness)

    def test_verify_wrong_commitment(self):
        from pqvpn.zkp import BandwidthRangeZKP
        zkp = BandwidthRangeZKP()
        value = 500
        limit = 1000
        randomness = os.urandom(32)

        proof = zkp.prove_range(value, 0, limit, randomness)
        wrong_commitment = os.urandom(32)

        assert not zkp.verify_range(proof, wrong_commitment)


class TestBandwidthFunctions:
    def test_prove_and_verify_bandwidth(self):
        from pqvpn.zkp import prove_bandwidth_range, verify_bandwidth_range
        usage = 750
        limit = 1000
        randomness = os.urandom(32)

        proof = prove_bandwidth_range(usage, limit, randomness)
        assert verify_bandwidth_range(proof, proof.commitment)

    def test_verify_invalid_bandwidth(self):
        from pqvpn.zkp import prove_bandwidth_range
        usage = 1200  # Over limit
        limit = 1000
        randomness = os.urandom(32)

        with pytest.raises(ValueError):
            prove_bandwidth_range(usage, limit, randomness)