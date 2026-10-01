from pathlib import Path

import pytest

from flowstate.core.config import load_config

ROOT = Path(__file__).resolve().parents[2]


def test_shipped_config_loads_and_resolves_paths():
    cfg = load_config(ROOT / "config" / "gateway.toml")
    assert cfg.port == 9000
    assert cfg.policy_path == (ROOT / "config" / "policy.toml").resolve()
    assert cfg.gateway_key_path == (ROOT / "keys" / "gateway.key").resolve()


def test_unknown_keys_rejected(tmp_path):
    p = tmp_path / "g.toml"
    p.write_text('port = 1\nprot = 2\n')
    with pytest.raises(ValueError):
        load_config(p)
