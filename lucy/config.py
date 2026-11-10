"""Config is the authority for permissions. The catalog DB only holds observations."""
import copy
import json
import os
import socket
from pathlib import Path

KINDS = ("dropbox", "icloud", "raid", "local")
DEFAULTS = {
    "sources": {},
    "repos": {},
    "mcp_writes": False,
    "max_excerpt_bytes": 8000,
    "max_hash_bytes": 256 * 1024 * 1024,
}


def home():
    p = Path(os.environ.get("LUCY_HOME") or Path.home() / ".lucy")
    p.mkdir(parents=True, exist_ok=True, mode=0o700)
    return p


def device():
    return os.environ.get("LUCY_DEVICE") or socket.gethostname().split(".")[0]


def load():
    cfg = copy.deepcopy(DEFAULTS)
    p = home() / "config.json"
    if p.exists():
        cfg.update(json.loads(p.read_text()))
    return cfg


def save(cfg):
    p = home() / "config.json"
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, indent=2, sort_keys=True))
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)


def project_sources(cfg, project=None):
    """Sources a caller may use: never revoked ones, and only the named project's."""
    return {
        sid: s
        for sid, s in cfg["sources"].items()
        if not s.get("revoked") and (project is None or s["project"] == project)
    }


def projects(cfg):
    return sorted({s["project"] for s in cfg["sources"].values() if not s.get("revoked")})
