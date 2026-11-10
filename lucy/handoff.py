"""Handoff manifests. A file named in a handoff is checked live; a reference is not proof."""
import json
import os
import re

from . import access, adapters, catalog, config
from .redact import log, now, redact_obj

REF = re.compile(r"(?<![\w/:.-])(~?/?(?:[\w .@()+-]+/)*[\w.@()+-]+\.(?:md|txt|json|sql|html|css|pdf|csv|py|ts|tsx|js|jsx|"
                 r"png|jpg|jpeg|mov|mp4|wav|prproj|docx|xlsx|zip|toml|yaml|yml|sh))\b")


def _dir():
    d = config.home() / "handoffs"
    d.mkdir(exist_ok=True)
    return d


def check_file(cfg, con, project, ref):
    """Status of one required file, checked now:
    present | changed | remote | source_offline | not_downloaded | access_denied | not_found | never_checked"""
    sid, rel = ref.get("source"), ref.get("path", "")
    out = {"source": sid, "path": rel, "pinned_sha256": ref.get("sha256")}
    src = cfg["sources"].get(sid)
    if src is None:
        return {**out, "status": "never_checked", "detail": "this source is not set up on this device"}
    try:
        full = access.resolve(cfg, sid, rel, project)
    except access.Denied as e:
        return {**out, "status": "access_denied", "detail": str(e)}
    row = con.execute("select * from copies where source_id=? and relpath=?", (sid, rel)).fetchone()
    last = {"last_seen_at": row["last_seen_at"], "last_sha256": row["sha256"]} if row else {"last_seen_at": None}
    status, detail = adapters.source_state(src)
    if status == "remote":
        return {**out, "status": "remote", "detail": detail, **last}
    if status != "available":
        return {**out, "status": "source_offline", "detail": detail, **last}
    try:
        st = os.lstat(full)
    except FileNotFoundError:
        stub = os.path.join(os.path.dirname(full), "." + os.path.basename(full) + ".icloud")
        if os.path.lexists(stub):
            return {**out, "status": "not_downloaded", "detail": "iCloud placeholder; content not on this Mac"}
        return {**out, "status": "not_found", "detail": f"not in {sid} when checked", **last}
    except PermissionError:
        return {**out, "status": "access_denied", "detail": "the system refused access"}
    if adapters.classify(full, st, src["kind"]) == "placeholder":
        return {**out, "status": "not_downloaded", "detail": "cloud placeholder; content not on this Mac"}
    try:
        sha = catalog.sha256_file(full)
    except OSError as e:
        return {**out, "status": "access_denied", "detail": e.strerror}
    if ref.get("sha256") and sha != ref["sha256"]:
        return {**out, "status": "changed", "sha256": sha, "detail": "content differs from the version the handoff pinned"}
    return {**out, "status": "present", "sha256": sha, "size": st.st_size}


def create(cfg, con, project, title, author, summary="", decisions=(), unfinished=(), blockers=(),
           next_steps=(), files=(), excluded=()):
    if project not in config.projects(cfg):
        raise PermissionError(f"project '{project}' has no approved source")
    required = []
    for f in files:
        c = check_file(cfg, con, project, f)
        # Pin the hash only when the content was actually read just now.
        required.append({"source": c["source"], "path": c["path"], "sha256": c.get("sha256"),
                         "size": c.get("size"), "status_at_creation": c["status"], "verified_at": now()})
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:40] or "handoff"
    hid = f"{project}-{now()[:19].replace(':', '').replace('-', '')}-{slug}"
    doc = redact_obj({
        "id": hid, "project": project, "title": title, "author": author, "created_at": now(),
        "created_on_device": config.device(), "summary": summary,
        "decisions": list(decisions), "unfinished": list(unfinished), "blockers": list(blockers),
        "next_steps": list(next_steps), "required_files": required,
        "intentionally_excluded": [dict(e) for e in excluded],
    })
    (_dir() / f"{hid}.json").write_text(json.dumps(doc, indent=2))
    log("handoff_saved", id=hid, project=project, files=len(required))
    return doc


def load(hid):
    p = _dir() / f"{os.path.basename(hid)}.json"
    return json.loads(p.read_text())


def list_all(cfg, project=None):
    out = []
    for p in sorted(_dir().glob("*.json")):
        d = json.loads(p.read_text())
        if d["project"] in config.projects(cfg) and (project is None or d["project"] == project):
            out.append({"id": d["id"], "project": d["project"], "title": d["title"], "created_at": d["created_at"]})
    return out


def validate(cfg, con, hid):
    doc = load(hid)
    if doc["project"] not in config.projects(cfg):
        raise access.Denied(f"project '{doc['project']}' is not approved")
    checks = [check_file(cfg, con, doc["project"], f) for f in doc["required_files"]]
    for e in doc.get("intentionally_excluded", []):
        checks.append({"path": e.get("path"), "status": "intentionally_excluded", "detail": e.get("reason", "")})
    problems = [c for c in checks if c["status"] not in ("present", "intentionally_excluded")]
    return {"id": doc["id"], "project": doc["project"], "title": doc["title"], "checked_at": now(),
            "complete": bool(doc["required_files"]) and not problems,
            "summary": {s: sum(1 for c in checks if c["status"] == s) for s in sorted({c["status"] for c in checks})},
            "files": checks,
            "note": "" if doc["required_files"] else "this handoff lists no required files, so completeness is unproven"}


def check_refs(cfg, con, source_id, relpath, project=None):
    """Read a handoff document that already exists and check every file it mentions."""
    full = access.resolve(cfg, source_id, relpath, project)
    src = cfg["sources"][source_id]
    status, detail = adapters.source_state(src)
    if status != "available":
        return {"status": "source_offline", "detail": detail}
    if adapters.classify(full, os.lstat(full), src["kind"]) != "readable":
        return {"status": "not_downloaded"}
    with open(full, "rb") as f:
        text = f.read(512 * 1024).decode("utf-8", errors="replace")
    sids = list(config.project_sources(cfg, src["project"]))
    offline = [s for s in sids if adapters.source_state(cfg["sources"][s])[0] != "available"]
    seen, results = set(), []
    for m in REF.finditer(text):
        ref = m.group(1).strip()
        if ref in seen or ref == os.path.basename(relpath):
            continue
        if re.fullmatch(r"[A-Z][A-Za-z0-9]*\.js", ref):
            continue  # a library name such as Node.js, not a file
        seen.add(ref)
        found = []
        if ref.startswith(("~", "/")):
            # An absolute path counts only if it falls inside an approved root of this project.
            absolute = os.path.realpath(os.path.expanduser(ref))
            for s2 in sids:
                root = os.path.realpath(cfg["sources"][s2]["root"])
                if absolute.startswith(root + os.sep):
                    c = check_file(cfg, con, src["project"], {"source": s2, "path": os.path.relpath(absolute, root)})
                    if c["status"] in ("present", "not_downloaded"):
                        found.append({"source": s2, "path": c["path"], "status": c["status"]})
        for cand in (ref, os.path.join(os.path.dirname(relpath), ref)):
            if found:
                break
            cand = os.path.normpath(cand)
            if cand.startswith(("..", "/", "~")):
                continue
            c = check_file(cfg, con, src["project"], {"source": source_id, "path": cand})
            if c["status"] in ("present", "not_downloaded"):
                found.append({"source": source_id, "path": cand, "status": c["status"]})
                break
        if not found:
            q = "(relpath=? or relpath like ?)" if "/" in ref else "name=?"
            params = (ref.lstrip("~/"), "%/" + ref.lstrip("~/")) if "/" in ref else (ref,)
            rows = con.execute(
                f"select * from copies where source_id in ({','.join('?' * len(sids))}) and gone=0 and {q} limit 5",
                (*sids, *params)).fetchall()
            for r in rows:
                # The catalog can be stale: confirm each hit against the live source.
                c = check_file(cfg, con, src["project"], {"source": r["source_id"], "path": r["relpath"]})
                if c["status"] in ("present", "not_downloaded"):
                    found.append({"source": r["source_id"], "path": r["relpath"], "status": c["status"]})
                elif c["status"] in ("source_offline", "remote"):
                    found.append({"source": r["source_id"], "path": r["relpath"], "status": c["status"],
                                  "last_seen_at": r["last_seen_at"]})
        live = [f for f in found if f["status"] in ("present", "not_downloaded")]
        status = "found" if live else ("last_known_only_source_offline" if found else "not_found_in_sources_checked")
        results.append({"reference": ref, "status": status, "found": found})
    missing = [r["reference"] for r in results if r["status"] == "not_found_in_sources_checked"]
    return {"status": "ok", "document": f"{source_id}:{relpath}", "references": len(results),
            "missing": missing, "sources_checked": sids, "sources_offline_so_not_checked": offline,
            "results": results}
