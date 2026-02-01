"""
Pydantic-based configuration schema for PQVPN.
This module exposes `ConfigModel` used by `main.py` to validate runtime config.
It's optional: if pydantic is not installed, `main.py` will continue but will log a warning.
"""

from __future__ import annotations
from typing import Optional, List, Dict, Any

try:
    import importlib as _importlib

    _pyd = _importlib.import_module("pydantic")
    BaseModel = getattr(_pyd, "BaseModel")
    Field = getattr(_pyd, "Field")
    _HAS_PYDANTIC = True
except Exception:
    # Provide lightweight fallback to avoid hard failure when pydantic is absent.
    class BaseModel:  # type: ignore
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

    def Field(default=None, **kwargs):  # type: ignore
        return default

    _HAS_PYDANTIC = False


class KDFConfig(BaseModel):
    time_cost: Optional[int] = Field(3, description="Argon2 time cost")
    memory_cost_kib: Optional[int] = Field(65536, description="Argon2 memory (KiB)")
    parallelism: Optional[int] = Field(4, description="Argon2 parallelism")


class SecurityConfig(BaseModel):
    strict_sig_verify: Optional[bool] = Field(False)
    tofu: Optional[bool] = Field(True)
    strict_tofu: Optional[bool] = Field(False)
    allowlist: Optional[List[str]] = Field(default_factory=list)
    known_peers_file: Optional[str] = Field("known_peers.yaml")
    kdf: Optional[KDFConfig] = Field(default_factory=KDFConfig)
    handshake_per_minute_per_ip: Optional[int] = Field(10)
    handshake_retries: Optional[int] = Field(1)
    handshake_backoff_base: Optional[float] = Field(2.0)
    handshake_backoff_factor: Optional[float] = Field(2.0)


class NetworkConfig(BaseModel):
    bind_host: Optional[str] = Field("0.0.0.0")
    listen_port: Optional[int] = Field(9000)
    max_concurrent_datagrams: Optional[int] = Field(200)


class KeysConfig(BaseModel):
    persist: Optional[bool] = Field(False)
    dir: Optional[str] = Field("keys")


class MetricsConfig(BaseModel):
    enabled: Optional[bool] = Field(False)
    host: Optional[str] = Field("127.0.0.1")
    port: Optional[int] = Field(9100)


class PeerConfig(BaseModel):
    nickname: str


class ConfigModel(BaseModel):
    peer: PeerConfig
    network: Optional[NetworkConfig] = Field(default_factory=NetworkConfig)
    security: Optional[SecurityConfig] = Field(default_factory=SecurityConfig)
    keys: Optional[KeysConfig] = Field(default_factory=KeysConfig)
    metrics: Optional[MetricsConfig] = Field(default_factory=MetricsConfig)
    bootstrap: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    node: Optional[Dict[str, Any]] = Field(default_factory=dict)


__all__ = [
    "ConfigModel",
    "SecurityConfig",
    "NetworkConfig",
    "MetricsConfig",
    "_HAS_PYDANTIC",
]
