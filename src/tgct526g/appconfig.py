"""Non-secret user preferences (last target, username, admin port)."""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any


def _config_dir() -> str:
    candidates = [
        os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), "TGCT526G"),
        os.path.join(tempfile.gettempdir(), "TGCT526G"),
        os.getcwd(),
    ]
    for path in candidates:
        try:
            os.makedirs(path, exist_ok=True)
            probe = os.path.join(path, ".write-test")
            with open(probe, "w", encoding="utf-8") as handle:
                handle.write("ok")
            os.remove(probe)
            return path
        except OSError:
            continue
    return "."


def config_path() -> str:
    return os.path.join(_config_dir(), "config.json")


def load_config() -> dict[str, Any]:
    try:
        with open(config_path(), "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_config(data: dict[str, Any]) -> None:
    path = config_path()
    temp = path + ".tmp"
    try:
        with open(temp, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
        os.replace(temp, path)
    except OSError:
        try:
            os.remove(temp)
        except OSError:
            pass
