#!/usr/bin/env python3
"""
Manual testing script for PQVPN modularity.
"""

import sys
import os
sys.path.insert(0, ".")

def test_config_modularity():
    """Test config module."""
    from src.pqvpn.config import Config
    print("✓ Config module imported successfully")

    config = Config()
    config.set_nested("test", "key", value="value")
    assert config.get("test", "key") == "value"
    print("✓ Config module basic functionality works")

def test_plugins_modularity():
    """Test plugins module."""
    from src.pqvpn.plugins import PluginManager

    print("✓ Plugins module imported successfully")

    manager = PluginManager()
    print(f"✓ Plugin manager created, discovered plugins: {manager.discover_plugins()}")

    # Test loading sample plugin
    success = manager.load_plugin("sample_plugin")
    if success:
        print("✓ Sample plugin loaded successfully")
        plugin = manager.get_plugin("sample_plugin")
        print(f"✓ Plugin info: {plugin.name} v{plugin.version}")
        manager.unload_plugin("sample_plugin")
        print("✓ Sample plugin unloaded successfully")
    else:
        print("✗ Failed to load sample plugin")

def test_network_modularity():
    """Test network module."""
    from src.pqvpn.network import NetworkManager, UDPTransport

    print("✓ Network module imported successfully")

    transport = UDPTransport()
    print(f"✓ UDP transport created: {transport.bind_host}:{transport.listen_port}")

    config = {"network": {"bind_host": "127.0.0.1"}}
    manager = NetworkManager(transport, config)
    print("✓ Network manager created")

def test_session_modularity():
    """Test session module."""
    from src.pqvpn.session import SessionManager

    print("✓ Session module imported successfully")

    config = {"session_timeout": 1800}
    manager = SessionManager(config)
    print("✓ Session manager created")

def test_discovery_modularity():
    """Test discovery module."""
    from src.pqvpn.discovery import Discovery

    print("✓ Discovery module imported successfully")

    # Mock node
    class MockNode:
        def __init__(self):
            self.config = {"discovery": {"enabled": False}}

    node = MockNode()
    discovery = Discovery(node)
    print(f"✓ Discovery created, enabled: {discovery.enabled}")

if __name__ == "__main__":
    print("=== PQVPN Modularity Manual Testing ===")
    try:
        test_config_modularity()
        test_plugins_modularity()
        test_network_modularity()
        test_session_modularity()
        test_discovery_modularity()
        print("\n✓ All modularity tests passed!")
    except Exception as e:
        print(f"\n✗ Modularity test failed: {e}")
        import traceback
        traceback.print_exc()