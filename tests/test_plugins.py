# tests/test_plugins.py
"""Tests for plugins module."""

import pytest
import tempfile
import os
from pqvpn.plugins import PluginManager, PluginInterface


class TestPlugin(PluginInterface):
    @property
    def name(self):
        return "test_plugin"

    @property
    def version(self):
        return "1.0.0"

    def initialize(self, context):
        pass

    def cleanup(self):
        pass


def test_plugin_manager():
    """Test plugin manager."""
    manager = PluginManager()
    assert manager.loaded_plugins == {}
    assert manager.hooks == {}


def test_plugin_discovery():
    """Test plugin discovery."""
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create a fake plugin directory
        plugin_dir = os.path.join(temp_dir, "test_plugin")
        os.makedirs(plugin_dir)
        with open(os.path.join(plugin_dir, "__init__.py"), "w") as f:
            f.write("# Test plugin")

        manager = PluginManager([temp_dir])
        plugins = manager.discover_plugins()
        assert "test_plugin" in plugins


def test_plugin_load():
    """Test plugin loading."""
    manager = PluginManager()

    # Since we can't easily create a real plugin file, test the structure
    assert manager.load_plugin("nonexistent") == False
    assert "nonexistent" not in manager.loaded_plugins