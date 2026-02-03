# src/pqvpn/config.py
"""
Configuration module for PQVPN.

Handles loading and validation of configuration from files and environment.
"""

import logging
import os
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# Inlined config_schema from main.py
try:
    # Start with the original logic from config_schema.py
    try:
        import importlib as _importlib

        _pyd = _importlib.import_module("pydantic")
        BaseModel = _pyd.BaseModel
        Field = _pyd.Field
        _HAS_PYDANTIC = True
    except Exception:
        # Lightweight fallback when pydantic not installed
        class BaseModel:  # type: ignore
            def __init__(self, **kwargs):
                for k, v in kwargs.items():
                    setattr(self, k, v)

        def Field(default=None, **kwargs):  # type: ignore
            return default

        _HAS_PYDANTIC = False

    class KDFConfig(BaseModel):
        time_cost = Field(2)
        memory_cost_kib = Field(65536)
        parallelism = Field(4)

    class SecurityConfig(BaseModel):
        strict_sig_verify = Field(False)
        tofu = Field(True)
        strict_tofu = Field(False)
        allowlist = Field(default_factory=list)
        known_peers_file = Field("known_peers.yaml")
        kdf = Field(default_factory=KDFConfig)
        handshake_per_minute_per_ip = Field(10)
        handshake_retries = Field(1)
        handshake_backoff_base = Field(2.0)
        handshake_backoff_factor = Field(2.0)

    class NetworkConfig(BaseModel):
        bind_host = Field("127.0.0.1")
        listen_port = Field(9000)
        max_concurrent_datagrams = Field(200)
        protocol = Field("pqvpn")  # Options: pqvpn, wireguard, openvpn

    class KeysConfig(BaseModel):
        persist = Field(False)
        dir = Field("keys")

    class MetricsConfig(BaseModel):
        enabled = Field(False)
        host = Field("127.0.0.1")
        port = Field(9100)

    class PeerConfig(BaseModel):
        nickname = Field("")

    class ConfigModel(BaseModel):
        peer = Field(PeerConfig())
        network = Field(default_factory=NetworkConfig)
        security = Field(default_factory=SecurityConfig)
        keys = Field(default_factory=KeysConfig)
        metrics = Field(default_factory=MetricsConfig)
        bootstrap = Field(default_factory=list)
        node = Field(default_factory=dict)

    # register shim module so `from config_schema import ...` works
    _config_module = 'config_schema'
    _config_module.ConfigModel = ConfigModel
    _config_module._HAS_PYDANTIC = _HAS_PYDANTIC
    _config_module.Field = Field
    import sys as _sys

    _sys.modules["config_schema"] = _config_module
except Exception:
    # swallow failures - PQVPN will continue without schema validation
    _HAS_PYDANTIC = False


class Config:
    """Configuration manager for PQVPN."""

    def __init__(self, config_file: str | None = None):
        self.config_file = config_file or self._find_config_file()
        self.data: dict[str, Any] = {}
        self.load()

    def _find_config_file(self) -> str:
        """Find configuration file in standard locations."""
        candidates = [
            "pqvpn.yaml",
            "pqvpn.yml",
            os.path.expanduser("~/.pqvpn/config.yaml"),
            "/etc/pqvpn/config.yaml"
        ]
        for candidate in candidates:
            if os.path.isfile(candidate):
                return candidate
        return "pqvpn.yaml"  # Default

    def load(self):
        """Load configuration from file and environment."""
        # Load from file
        if os.path.isfile(self.config_file):
            try:
                with open(self.config_file) as f:
                    file_config = yaml.safe_load(f) or {}
                self.data.update(file_config)
                logger.info(f"Loaded config from {self.config_file}")
            except Exception as e:
                logger.warning(f"Failed to load config from {self.config_file}: {e}")

        # Override with environment variables
        self._load_from_env()

        # Validate
        self.validate()

    def _load_from_env(self):
        """Load configuration from environment variables."""
        env_mappings = {
            'PQVPN_BIND_HOST': ('network', 'bind_host'),
            'PQVPN_LISTEN_PORT': ('network', 'listen_port'),
            'PQVPN_NICKNAME': ('peer', 'nickname'),
            'PQVPN_KEYS_DIR': ('keys', 'dir'),
            'PQVPN_DISCOVERY_ENABLED': ('discovery', 'enabled'),
        }

        for env_var, config_path in env_mappings.items():
            value = os.environ.get(env_var)
            if value is not None:
                self.set_nested(*config_path, value=value)
                logger.debug(f"Set {'.'.join(config_path)} = {value} from {env_var}")

    def set_nested(self, *keys, value):
        """Set a nested configuration value."""
        d = self.data
        for key in keys[:-1]:
            if key not in d:
                d[key] = {}
            d = d[key]
        d[keys[-1]] = value

    def get(self, *keys, default=None):
        """Get a nested configuration value."""
        d = self.data
        for key in keys:
            if isinstance(d, dict) and key in d:
                d = d[key]
            else:
                return default
        return d

    def validate(self):
        """Validate configuration against schema."""
        try:
            if _HAS_PYDANTIC:
                ConfigModel(**self.data)
                logger.info("Configuration validated successfully")
            else:
                logger.warning("Pydantic not available, skipping config validation")
        except Exception as e:
            logger.error(f"Configuration validation failed: {e}")
            raise

    def save(self):
        """Save configuration to file."""
        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            with open(self.config_file, 'w') as f:
                yaml.dump(self.data, f, default_flow_style=False)
            logger.info(f"Saved config to {self.config_file}")
        except Exception as e:
            logger.error(f"Failed to save config: {e}")

    def __getitem__(self, key):
        return self.data[key]

    def __setitem__(self, key, value):
        self.data[key] = value

    def __contains__(self, key):
        return key in self.data