#!/usr/bin/env python3
"""
Simple healthcheck for PQVPN repository: checks venv, liboqs, config parse, key dir permissions, and basic imports.
"""
import json
import os
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
venv = root / '.venv'
keys = root / 'keys'
config = root / 'config.yaml'

status = {
    'repo': str(root),
    'python': sys.executable,
    'venv_exists': venv.exists(),
    'config_exists': config.exists(),
    'keys_dir_exists': keys.exists(),
    'keys_permissions': None,
    'oqs': None,
}

# check keys permissions if present
try:
    if keys.exists():
        perms = oct(os.stat(keys).st_mode & 0o777)
        status['keys_permissions'] = perms
except Exception as e:
    status['keys_permissions'] = f'error: {e}'

# try to import oqs and list enabled mechanisms
try:
    import importlib
    oqs = importlib.import_module('oqs')
    if hasattr(oqs, 'get_enabled_sig_mechanisms'):
        status['oqs'] = {'ok': True, 'enabled_sigs': oqs.get_enabled_sig_mechanisms()}
    else:
        status['oqs'] = {'ok': False, 'reason': 'get_enabled_sig_mechanisms missing'}
except Exception as e:
    status['oqs'] = {'ok': False, 'error': str(e)}

# try to parse config quickly
try:
    import yaml
    with config.open('r') as f:
        cfg = yaml.safe_load(f)
    status['config_sample'] = {
        'peer': cfg.get('peer', {}) if isinstance(cfg, dict) else None,
        'network': 'present' if 'network' in cfg else 'missing',
    }
except Exception as e:
    status['config_sample'] = {'error': str(e)}

print(json.dumps(status, indent=2))
