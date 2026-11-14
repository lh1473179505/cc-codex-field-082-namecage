"""Load a certificate bundle, a policy, and a keyring. Path checks are not implemented here."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class LoadError(Exception):
    pass


def load_json(path: str | Path) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LoadError(str(exc)) from exc


def load_bundle(path: str | Path) -> dict[str, Any]:
    raw = load_json(path)
    certs = list(raw.get("certs") or [])
    return {
        "now": int(raw.get("now") or 0),
        "hostname": str(raw.get("hostname") or ""),
        "trust_anchors": list(raw.get("trust_anchors") or []),
        "leaf_id": raw.get("leaf_id"),
        "certs": certs,
    }


def load_policy(path: str | Path) -> dict[str, Any]:
    return load_json(path)


def load_keys(path: str | Path) -> dict[str, str]:
    raw = load_json(path)
    return {str(k): str(v) for k, v in raw.items()}
