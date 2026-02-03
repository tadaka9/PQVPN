# src/pqvpn/plugins.py
"""
Plugin system for PQVPN.

Allows loading and managing plugins for extensibility.
"""

import importlib.util
import logging
import os
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


class PluginInterface(ABC):
    """Base interface for PQVPN plugins."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin name."""
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version."""
        pass

    @abstractmethod
    def initialize(self, context: dict[str, Any]) -> None:
        """Initialize the plugin with context."""
        pass

    @abstractmethod
    def cleanup(self) -> None:
        """Cleanup plugin resources."""
        pass


class AuthPlugin(PluginInterface):
    """Authentication plugin interface."""

    @abstractmethod
    def authenticate(self, credentials: dict[str, Any]) -> bool:
        """Authenticate user/peer."""
        pass


class RoutingPlugin(PluginInterface):
    """Routing plugin interface."""

    @abstractmethod
    def route_packet(self, packet: bytes, source: str, destination: str) -> str | None:
        """Route a packet, return next hop or None."""
        pass


class EncryptionPlugin(PluginInterface):
    """Encryption plugin interface."""

    @abstractmethod
    def encrypt(self, data: bytes, key: bytes) -> bytes:
        """Encrypt data."""
        pass

    @abstractmethod
    def decrypt(self, data: bytes, key: bytes) -> bytes:
        """Decrypt data."""
        pass


class PluginManager:
    """Manages loading and execution of plugins."""

    def __init__(self, plugin_dirs: list[str] | None = None):
        self.plugin_dirs = plugin_dirs or [
            os.path.join(os.getcwd(), "plugins"),
            os.path.expanduser("~/.pqvpn/plugins"),
            "/usr/lib/pqvpn/plugins"
        ]
        self.loaded_plugins: dict[str, PluginInterface] = {}
        self.hooks: dict[str, list[Callable]] = {}

    def discover_plugins(self) -> list[str]:
        """Discover available plugins."""
        plugins = []
        for plugin_dir in self.plugin_dirs:
            if not os.path.isdir(plugin_dir):
                continue
            for item in os.listdir(plugin_dir):
                plugin_path = os.path.join(plugin_dir, item)
                if os.path.isdir(plugin_path) and os.path.isfile(os.path.join(plugin_path, "__init__.py")):
                    plugins.append(item)
                elif item.endswith(".py") and item != "__init__.py":
                    plugins.append(item[:-3])  # Remove .py
        return plugins

    def load_plugin(self, plugin_name: str, context: dict[str, Any] | None = None) -> bool:
        """Load a plugin by name."""
        if plugin_name in self.loaded_plugins:
            logger.warning(f"Plugin {plugin_name} already loaded")
            return True

        # Try to find and load the plugin
        plugin_module = None
        for plugin_dir in self.plugin_dirs:
            plugin_path = os.path.join(plugin_dir, f"{plugin_name}.py")
            if os.path.isfile(plugin_path):
                spec = importlib.util.spec_from_file_location(plugin_name, plugin_path)
                if spec and spec.loader:
                    plugin_module = importlib.util.module_from_spec(spec)
                    try:
                        spec.loader.exec_module(plugin_module)
                        break
                    except Exception as e:
                        logger.error(f"Failed to load plugin {plugin_name}: {e}")
                        return False

        if not plugin_module:
            logger.error(f"Plugin {plugin_name} not found")
            return False

        # Find the plugin class
        plugin_class = None
        for attr_name in dir(plugin_module):
            attr = getattr(plugin_module, attr_name)
            if (isinstance(attr, type) and
                issubclass(attr, PluginInterface) and
                attr != PluginInterface):
                plugin_class = attr
                break

        if not plugin_class:
            logger.error(f"No plugin class found in {plugin_name}")
            return False

        # Instantiate and initialize
        try:
            plugin_instance = plugin_class()
            plugin_instance.initialize(context or {})
            self.loaded_plugins[plugin_name] = plugin_instance
            logger.info(f"Loaded plugin {plugin_name} v{plugin_instance.version}")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize plugin {plugin_name}: {e}")
            return False

    def unload_plugin(self, plugin_name: str) -> bool:
        """Unload a plugin."""
        plugin = self.loaded_plugins.get(plugin_name)
        if not plugin:
            return False

        try:
            plugin.cleanup()
            del self.loaded_plugins[plugin_name]
            logger.info(f"Unloaded plugin {plugin_name}")
            return True
        except Exception as e:
            logger.error(f"Error unloading plugin {plugin_name}: {e}")
            return False

    def get_plugin(self, plugin_name: str) -> PluginInterface | None:
        """Get a loaded plugin instance."""
        return self.loaded_plugins.get(plugin_name)

    def register_hook(self, hook_name: str, callback: Callable):
        """Register a hook callback."""
        if hook_name not in self.hooks:
            self.hooks[hook_name] = []
        self.hooks[hook_name].append(callback)

    def call_hook(self, hook_name: str, *args, **kwargs):
        """Call all registered hooks for a hook name."""
        if hook_name in self.hooks:
            for callback in self.hooks[hook_name]:
                try:
                    callback(*args, **kwargs)
                except Exception as e:
                    logger.error(f"Hook {hook_name} callback failed: {e}")

    def list_plugins(self) -> list[str]:
        """List loaded plugins."""
        return list(self.loaded_plugins.keys())


# Global plugin manager instance
plugin_manager = PluginManager()