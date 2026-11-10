"""Explicit snapshots into Lucy's own content-addressed store, with verified restore.

A snapshot is a local, unencrypted copy under LUCY_HOME. It protects against a changed
or deleted original. It is not an off-site backup and not an encrypted one.
"""
import hashlib
import json
import os
import shutil
import tempfile

from . import access, adapters, config
from .redact import log, now


def _store():
    d = config.home() / "store"
    d.mkdir(exist_ok=True)
    return d


def _obj(sha):
    return _store() / sha[:2] / sha


def _ingest(path):
    h = hashlib.sha256()
    fd, tmp = tempfile.mkstemp(dir=_store())
    with os.fdopen(fd, "wb") as out, open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
            out.write(chunk)
    sha = h.hexdigest()
    dest = _obj(sha)
    dest.parent.mkdir(exist_ok=True)
    if dest.exists():
        os.unlink(tmp)
    else:
        os.replace(tmp, dest)
        os.chmod(dest, 0o400)
    return sha


def create(cfg, con, sid, prefix=""):
    src = cfg["sources"].get(sid)
    if src is None or src.get("revoked"):
        raise access.Denied(f"source '{sid}' is not approved")
    status, detail = adapters.source_state(src)
    if status != "available":
        raise access.Denied(f"source is {status}: {detail}")
    files, skipped = {}, []
    for rel, path, size, _mtime, avail in adapters.walk(src):
        if prefix and not (rel == prefix or rel.startswith(prefix.rstrip("/") + "/")):
            continue
        if avail != "readable":
            skipped.append({"path": rel, "reason": avail})
            continue
        try:
            access.resolve(cfg, sid, rel)
            files[rel] = {"sha256": _ingest(path), "size": size}
        except (OSError, access.Denied) as e:
            skipped.append({"path": rel, "reason": str(e)})
    sid_dir = config.home() / "snapshots"
    sid_dir.mkdir(exist_ok=True)
    snap_id = f"{sid}-{now()[:19].replace(':', '').replace('-', '')}"
    doc = {"id": snap_id, "source": sid, "project": src["project"], "prefix": prefix, "created_at": now(),
           "files": files, "skipped_not_copied": skipped,
           "state": "copied, not yet verified. Run verify, and restore once, before trusting it."}
    (sid_dir / f"{snap_id}.json").write_text(json.dumps(doc, indent=2))
    log("snapshot", id=snap_id, files=len(files), skipped=len(skipped))
    return {"id": snap_id, "files_copied": len(files), "skipped_not_copied": skipped}


def load(snap_id):
    return json.loads((config.home() / "snapshots" / f"{os.path.basename(snap_id)}.json").read_text())


def _sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify(snap_id):
    doc, bad = load(snap_id), []
    for rel, meta in doc["files"].items():
        p = _obj(meta["sha256"])
        if not p.exists():
            bad.append({"path": rel, "problem": "stored copy is missing"})
        elif _sha(p) != meta["sha256"]:
            bad.append({"path": rel, "problem": "stored copy is corrupted"})
    return {"id": doc["id"], "files": len(doc["files"]), "verified": not bad, "problems": bad}


def restore(snap_id, dest):
    """Write the snapshot into a new or empty folder. Never overwrites anything."""
    doc = load(snap_id)
    dest = os.path.abspath(os.path.expanduser(dest))
    if os.path.exists(dest) and os.listdir(dest):
        raise access.Denied("restore target must be a new or empty folder; originals are never overwritten")
    check = verify(snap_id)
    if not check["verified"]:
        return {"restored": False, **check}
    os.makedirs(dest, exist_ok=True)
    for rel, meta in doc["files"].items():
        if os.path.isabs(rel) or ".." in rel.split("/"):
            raise access.Denied(f"unsafe path in snapshot: {rel}")
        out = os.path.join(dest, rel)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        shutil.copyfile(_obj(meta["sha256"]), out)
        if _sha(out) != meta["sha256"]:
            return {"restored": False, "problem": f"{rel} did not match after copy"}
    log("restore", id=snap_id, files=len(doc["files"]))
    return {"restored": True, "id": doc["id"], "files": len(doc["files"]), "dest": dest}
