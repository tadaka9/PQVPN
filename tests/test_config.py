# tests/test_config.py
"""Tests for config module."""

import os
import tempfile

from pqvpn.config import Config


def test_config_init():
    """Test config initialization."""
    config = Config()
    assert isinstance(config.data, dict)


def test_config_load_env():
    """Test config loading from environment."""
    os.environ["PQVPN_BIND_HOST"] = "127.0.0.1"
    os.environ["PQVPN_LISTEN_PORT"] = "8080"

    config = Config()
    assert config.get("network", "bind_host") == "127.0.0.1"
    assert config.get("network", "listen_port") == "8080"

    # Cleanup
    del os.environ["PQVPN_BIND_HOST"]
    del os.environ["PQVPN_LISTEN_PORT"]


def test_config_save():
    """Test config saving."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write("peer:\n  nickname: test\n")
        temp_file = f.name

    config = Config(temp_file)
    config.set_nested("peer", "nickname", "updated")
    config.save()

    # Reload and check
    new_config = Config(temp_file)
    assert new_config.get("peer", "nickname") == "updated"

    os.unlink(temp_file)