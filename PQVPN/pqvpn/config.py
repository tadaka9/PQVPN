"""
Config Module for PQVPN.
- Handles configuration loading and validation.
- Supports optional dependencies (e.g., pydantic).
"""

import yaml
from typing import Any, Dict
try:
    from pydantic import BaseModel, Field
except ImportError:
    # Minimal fallback if Pydantic is not available
    class BaseModel:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

        def dict(self) -> Dict[str, Any]:
            return self.__dict__

    def Field(default=None, **_kwargs):
        return default


class KDFConfig(BaseModel):
    time_cost: int = Field(3)
    memory_cost_kib: int = Field(65536)
    parallelism: int = Field(4)


class SecurityConfig(BaseModel):
    strict_sig_verify: bool = Field(False)
    tofu: bool = Field(True)
    strict_tofu: bool = Field(False)
    allowlist: list[str] = Field(default_factory=list)
    known_peers_file: str = Field("known_peers.yaml")
    kdf: KDFConfig = Field(default_factory=KDFConfig)
    handshake_per_minute_per_ip: int = Field(10)
    handshake_retries: int = Field(1)
    handshake_backoff_base: float = Field(2.0)
    handshake_backoff_factor: float = Field(2.0)


class NetworkConfig(BaseModel):
    bind_host: str = Field("0.0.0.0")
    listen_port: int = Field(9000)
    max_concurrent_datagrams: int = Field(200)


class KeysConfig(BaseModel):
    persist: bool = Field(False)
    dir: str = Field("keys")


class MetricsConfig(BaseModel):
    enabled: bool = Field(False)
    host: str = Field("127.0.0.1")
    port: int = Field(9100)


class PeerConfig(BaseModel):
    nickname: str = Field("")


class ConfigModel(BaseModel):
    peer: PeerConfig = Field(default_factory=PeerConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    keys: KeysConfig = Field(default_factory=KeysConfig)
    metrics: MetricsConfig = Field(default_factory=MetricsConfig)
    bootstrap: list[dict] = Field(default_factory=list)
    node: dict = Field(default_factory=dict)


def load_config(file_path: str) -> ConfigModel:
    """Load and parse a YAML configuration file."""
    try:
        with open(file_path, "r") as f:
            raw_config = yaml.safe_load(f)
        return ConfigModel(**raw_config)
    except Exception as e:
        raise RuntimeError(f"Failed to load configuration from {file_path}: {e}")
