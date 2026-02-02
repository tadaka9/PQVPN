"""
Tests for pqvpn.zero_trust module.
"""

import pytest
from pqvpn.zero_trust import ZeroTrustEngine, Policy, RequestContext, create_default_policies


class TestZeroTrustEngine:
    def test_initialization(self):
        engine = ZeroTrustEngine()
        assert engine.policies == {}
        assert engine.monitoring_threads == {}
        assert engine.monitoring_active == True

    def test_add_policy(self):
        engine = ZeroTrustEngine()
        policy = Policy("test", lambda ctx: True, "allow")
        engine.add_policy(policy)
        assert "test" in engine.policies

    def test_remove_policy(self):
        engine = ZeroTrustEngine()
        policy = Policy("test", lambda ctx: True, "allow")
        engine.add_policy(policy)
        engine.remove_policy("test")
        assert "test" not in engine.policies

    def test_verify_request_allow(self):
        engine = ZeroTrustEngine()
        policy = Policy("allow_all", lambda ctx: True, "allow")
        engine.add_policy(policy)

        request = RequestContext(b"session1", b"peer1", "connect", {})
        result = engine.verify_request(request)
        assert result == "allow"

    def test_verify_request_deny(self):
        engine = ZeroTrustEngine()
        policy = Policy("deny_all", lambda ctx: True, "deny")
        engine.add_policy(policy)

        request = RequestContext(b"session1", b"peer1", "connect", {})
        result = engine.verify_request(request)
        assert result == "deny"

    def test_verify_request_challenge(self):
        engine = ZeroTrustEngine()
        policy = Policy("challenge_admin", lambda ctx: ctx.get("action") == "admin", "challenge")
        engine.add_policy(policy)

        request = RequestContext(b"session1", b"peer1", "admin", {})
        result = engine.verify_request(request)
        assert result == "challenge"

    def test_authorize_action(self):
        engine = ZeroTrustEngine()
        policies = {"allowed_actions": ["read", "write"]}
        result = engine.authorize_action("read", b"user1", policies)
        assert result == True

        result = engine.authorize_action("delete", b"user1", policies)
        assert result == False

    def test_start_stop_monitoring(self):
        engine = ZeroTrustEngine()
        session_id = b"session1"
        engine.start_continuous_monitor(session_id)
        assert session_id in engine.monitoring_threads

        engine.stop_continuous_monitor(session_id)
        assert session_id not in engine.monitoring_threads

    def test_shutdown(self):
        engine = ZeroTrustEngine()
        session_id = b"session1"
        engine.start_continuous_monitor(session_id)
        engine.shutdown()
        assert engine.monitoring_active == False
        assert engine.monitoring_threads == {}


class TestDefaultPolicies:
    def test_create_default_policies(self):
        policies = create_default_policies()
        assert "unknown_peer" in policies
        assert "high_risk" in policies

        # Test unknown peer policy
        policy = policies["unknown_peer"]
        assert policy.action == "deny"

        # Test high risk policy
        policy = policies["high_risk"]
        assert policy.action == "challenge"


class TestRequestContext:
    def test_request_context_creation(self):
        import time
        ctx = RequestContext(b"session1", b"peer1", "connect", {"key": "value"})
        assert ctx.session_id == b"session1"
        assert ctx.peer_id == b"peer1"
        assert ctx.action == "connect"
        assert ctx.metadata == {"key": "value"}
        assert isinstance(ctx.timestamp, float)


class TestLeastPrivilege:
    def test_enforce_least_privilege_allowed(self):
        engine = ZeroTrustEngine()
        identity = b"user1"
        resource = "session"
        action = "create"

        result = engine.enforce_least_privilege(identity, resource, action)
        assert result == True

    def test_enforce_least_privilege_denied(self):
        engine = ZeroTrustEngine()
        identity = b"user1"
        resource = "admin"
        action = "delete"

        result = engine.enforce_least_privilege(identity, resource, action)
        assert result == False  # No permission for admin.delete


class TestMicroSegmentation:
    def test_micro_segmentation_allowed(self):
        engine = ZeroTrustEngine()
        result = engine.check_micro_segmentation("network", "crypto", "read")
        assert result == True

    def test_micro_segmentation_denied(self):
        engine = ZeroTrustEngine()
        result = engine.check_micro_segmentation("network", "tun", "admin")  # Invalid action
        assert result == False

    def test_micro_segmentation_invalid_source(self):
        engine = ZeroTrustEngine()
        result = engine.check_micro_segmentation("invalid", "crypto", "read")
        assert result == False


class TestContinuousAuthentication:
    def test_continuous_authenticate(self):
        engine = ZeroTrustEngine()
        session_id = b"session1"
        challenge = b"challenge"

        result = engine.continuous_authenticate(session_id, challenge)
        assert result == True  # Placeholder always returns True


class TestEnhancedDefaultPolicies:
    def test_enhanced_default_policies(self):
        policies = create_default_policies()
        assert "unknown_peer" in policies
        assert "high_risk" in policies
        assert "least_privilege" in policies
        assert "micro_segmentation" in policies

        # Test least privilege policy
        policy = policies["least_privilege"]
        assert policy.action == "deny"

        # Test micro-segmentation policy
        policy = policies["micro_segmentation"]
        assert policy.action == "deny"