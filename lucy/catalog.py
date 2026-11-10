"""The shared catalog: which copy is where, can it be read, and do copies match."""
import hashlib
import os

from . import adapters, config
from .redact import log, now


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _set_state(con, sid, status, detail, files=None, available=False):
    t = now()
    con.execute("insert or ignore into source_state(source_id) values(?)", (sid,))
    con.execute("update source_state set status=?, detail=?, last_scan_at=? where source_id=?", (status, detail, t, sid))
    if available:
        con.execute("update source_state set last_available_at=?, files=? where source_id=?", (t, files, sid))
    con.commit()


def scan(cfg, con, sid):
    src = cfg["sources"].get(sid)
    if src is None or src.get("revoked"):
        return {"source": sid, "status": "denied", "detail": "not approved or revoked"}
    status, detail = adapters.source_state(src)
    known = con.execute("select count(*) from copies where source_id=? and gone=0", (sid,)).fetchone()[0]
    if status != "available":
        # An absent source is never read as deletion: last-known observations stay as they are.
        _set_state(con, sid, status, detail)
        log("scan", source=sid, status=status)
        return {"source": sid, "status": status, "detail": detail, "last_known_copies_retained": known}

    entries = list(adapters.walk(src))
    if not entries and known:
        detail = f"root is present but empty while {known} files were known; treated as not synced, nothing marked gone"
        _set_state(con, sid, "suspect_empty", detail)
        return {"source": sid, "status": "suspect_empty", "detail": detail, "last_known_copies_retained": known}

    t = now()
    limit = src.get("max_hash_bytes", cfg["max_hash_bytes"])
    counts = {"readable": 0, "placeholder": 0, "placeholder_dir": 0, "symlink": 0, "denied": 0, "unreadable": 0}
    hashed = 0
    for rel, path, size, mtime, avail in entries:
        row = con.execute("select * from copies where source_id=? and relpath=?", (sid, rel)).fetchone()
        sha, note = None, None
        if avail == "readable":
            if row and row["sha256"] and row["size"] == size and row["mtime"] == mtime and row["availability"] == "readable":
                sha = row["sha256"]
            elif size > limit:
                note = "not hashed: over size limit"
            else:
                try:
                    sha = sha256_file(path)
                    hashed += 1
                except PermissionError:
                    avail = "denied"
                except OSError as e:
                    avail, note = "unreadable", e.strerror
        elif avail.startswith("placeholder"):
            note = "content not on this Mac; not read"
        counts[avail] = counts.get(avail, 0) + 1
        con.execute(
            "insert into copies(source_id,relpath,name,size,mtime,availability,sha256,note,first_seen_at,last_seen_at,gone)"
            " values(?,?,?,?,?,?,?,?,?,?,0) on conflict(source_id,relpath) do update set"
            " size=excluded.size, mtime=excluded.mtime, availability=excluded.availability, sha256=excluded.sha256,"
            " note=excluded.note, last_seen_at=excluded.last_seen_at, gone=0",
            (sid, rel, os.path.basename(rel.rstrip("/")), size, mtime, avail, sha, note, t, t))
        if sha and (row is None or row["sha256"] != sha):
            con.execute("insert into copy_history values(?,?,?,?,?,?)", (sid, rel, sha, size, mtime, t))
    gone = con.execute("update copies set gone=1 where source_id=? and gone=0 and last_seen_at<>?", (sid, t)).rowcount
    _set_state(con, sid, "available", git_note(src["root"]), files=len(entries), available=True)
    log("scan", source=sid, status="available", files=len(entries), hashed=hashed, gone=gone)
    return {"source": sid, "status": "available", "files": len(entries), "hashed_now": hashed,
            "no_longer_present": gone, "by_availability": {k: v for k, v in counts.items() if v}}


def git_head(repo):
    """Read HEAD straight from .git files. Never runs git inside an untrusted repo."""
    g = os.path.join(repo, ".git")
    try:
        head = open(os.path.join(g, "HEAD")).read().strip()
        if not head.startswith("ref: "):
            return head, "detached"
        ref = head[5:]
        try:
            return open(os.path.join(g, ref)).read().strip(), ref
        except OSError:
            for line in open(os.path.join(g, "packed-refs")):
                if line.strip().endswith(" " + ref):
                    return line.split()[0], ref
    except OSError:
        pass
    return None, None


def git_note(root):
    commit, ref = git_head(root)
    return f"git {ref} @ {commit}" if commit else ""


def _copy(cfg, row):
    src = cfg["sources"][row["source_id"]]
    return {"source": row["source_id"], "kind": src["kind"], "device": src.get("device"),
            "path": row["relpath"], "size": row["size"], "modified": row["mtime"],
            "availability": row["availability"], "sha256": row["sha256"], "note": row["note"],
            "last_seen_at": row["last_seen_at"], "still_present_at_last_scan": not row["gone"]}


def _in(sids):
    return ",".join("?" * len(sids))


def source_status(cfg, con, project=None):
    out = []
    for sid, src in config.project_sources(cfg, project).items():
        status, detail = adapters.source_state(src)
        row = con.execute("select * from source_state where source_id=?", (sid,)).fetchone()
        out.append({"source": sid, "kind": src["kind"], "project": src["project"], "device": src.get("device"),
                    "root": src["root"], "status_now": status, "detail": detail,
                    "last_available_at": row["last_available_at"] if row else None,
                    "last_scan_at": row["last_scan_at"] if row else None,
                    "files_at_last_good_scan": row["files"] if row else None,
                    "scan_note": row["detail"] if row else "never scanned"})
    return out


def search(cfg, con, query, project=None, limit=50):
    sids = list(config.project_sources(cfg, project))
    if not sids:
        return []
    like = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    rows = con.execute(
        f"select * from copies where source_id in ({_in(sids)}) and relpath like ? escape '\\' "
        "order by gone, relpath limit ?", (*sids, like, min(int(limit), 200))).fetchall()
    return [_copy(cfg, r) for r in rows]


def versions(cfg, con, project, name):
    """All copies of one logical asset, grouped by content, with ancestry evidence.
    Modification time is shown as evidence only; it never picks a winner."""
    sids = list(config.project_sources(cfg, project))
    if not sids:
        return {"asset": name, "copies": 0, "verdict": "no approved sources"}
    rows = con.execute(
        f"select * from copies where source_id in ({_in(sids)}) and gone=0 and (relpath=? or name=?)",
        (*sids, name, name)).fetchall()
    groups, unread = {}, []
    for r in rows:
        (groups.setdefault(r["sha256"], []) if r["sha256"] else unread).append(r)
    superseded, evidence = set(), []
    for sha, members in groups.items():
        for r in members:
            past = {h["sha256"] for h in con.execute(
                "select sha256 from copy_history where source_id=? and relpath=?", (r["source_id"], r["relpath"]))}
            for other in groups:
                if other != sha and other in past:
                    superseded.add(other)
                    evidence.append(f"{r['source_id']}:{r['relpath']} used to hold {other[:12]} and now holds {sha[:12]}")
    live = [s for s in groups if s not in superseded]
    if len(groups) <= 1:
        verdict = "identical" if groups else "no readable copy"
    elif len(live) == 1:
        verdict = f"suggested current: {live[0][:12]} (by observed history, not by date)"
    else:
        verdict = "divergent: no history proves which is current; needs your decision"
    return {"asset": name, "copies": len(rows), "verdict": verdict, "ancestry_evidence": evidence,
            "versions": [{"sha256": s, "superseded": s in superseded, "copies": [_copy(cfg, r) for r in m]}
                         for s, m in groups.items()],
            "content_not_read": [_copy(cfg, r) for r in unread]}


def conflicts(cfg, con, project=None, by_name=False):
    """Same path (or same file name) in more than one source with different content."""
    sids = list(config.project_sources(cfg, project))
    if not sids:
        return []
    col = "name" if by_name else "relpath"
    keys = con.execute(
        f"select {col} k from copies where source_id in ({_in(sids)}) and gone=0 and sha256 is not null "
        f"group by {col} having count(distinct sha256)>1 and count(distinct source_id)>1 order by {col} limit 500",
        sids).fetchall()
    out = []
    for k in keys:
        rows = con.execute(
            f"select * from copies where source_id in ({_in(sids)}) and gone=0 and sha256 is not null and {col}=?",
            (*sids, k["k"])).fetchall()
        out.append({"asset": k["k"], "copies": [_copy(cfg, r) for r in rows]})
    return out


def duplicates(cfg, con, project=None):
    sids = list(config.project_sources(cfg, project))
    if not sids:
        return []
    shas = con.execute(
        f"select sha256, count(*) n, max(size) size from copies where source_id in ({_in(sids)}) and gone=0 "
        "and sha256 is not null and size>0 group by sha256 having count(distinct source_id)>1 "
        "order by size desc limit 500", sids).fetchall()
    out = []
    for s in shas:
        rows = con.execute(f"select * from copies where source_id in ({_in(sids)}) and gone=0 and sha256=?",
                           (*sids, s["sha256"])).fetchall()
        out.append({"sha256": s["sha256"], "size": s["size"],
                    "copies": [f"{r['source_id']}:{r['relpath']}" for r in rows]})
    return out


def revoke(cfg, con, sid):
    """Revocation stops all future access. Cache policy: the catalog rows for the source
    (paths, sizes, hashes, history) are deleted. Snapshots already made are kept until
    removed by hand, and are listed so that is visible."""
    if sid not in cfg["sources"]:
        return {"source": sid, "status": "unknown"}
    cfg["sources"][sid]["revoked"] = True
    config.save(cfg)
    n = con.execute("delete from copies where source_id=?", (sid,)).rowcount
    con.execute("delete from copy_history where source_id=?", (sid,))
    con.execute("delete from source_state where source_id=?", (sid,))
    con.commit()
    snaps = [p.name for p in (config.home() / "snapshots").glob(f"{sid}-*.json")]
    log("revoke", source=sid, catalog_rows_deleted=n)
    return {"source": sid, "status": "revoked", "catalog_rows_deleted": n, "snapshots_kept": snaps}
