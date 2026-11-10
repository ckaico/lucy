"""Read-only repo baseline. Reads files only: never runs repo scripts, never tests a
credential, never contacts a network. The built-in pattern scan is a floor, not an audit;
every check that did not run is recorded as a coverage gap."""
import configparser
import json
import os
import shutil
import subprocess
import tempfile

from . import adapters
from .catalog import git_head
from .redact import RULES, log, now, redact

NOISE = ("node_modules/", "venv/", "site-packages/", ".next/", "dist/", "build/")
EXTERNAL = {
    "trufflehog": "secret scanning with verification",
    "semgrep": "source-code analysis",
}


def _noise(path):
    return any(("/" + path).find("/" + n) >= 0 for n in NOISE)


def run_gitleaks(root, mode):
    """mode 'dir' reads working files; 'git' reads commit history. Secrets are fully redacted
    by gitleaks before Lucy sees them. Returns (rows, status, detail)."""
    exe = shutil.which("gitleaks")
    if not exe:
        return [], "not_run", "not installed"
    with tempfile.TemporaryDirectory() as tmp:
        report = os.path.join(tmp, "r.json")
        try:
            p = subprocess.run([exe, mode, root, "--redact=100", "--report-format", "json", "--report-path", report,
                                "--exit-code", "0", "--no-banner", "--log-level", "error"],
                               capture_output=True, text=True, timeout=900, cwd=tmp)
            data = json.load(open(report))
        except (subprocess.TimeoutExpired, OSError, ValueError) as e:
            return [], "failed", f"{type(e).__name__}"
    rows = []
    for f in data:
        rel = os.path.relpath(f["File"], root) if os.path.isabs(f["File"]) else f["File"]
        if _noise(rel):
            continue
        where = f" in commit {f['Commit'][:10]}" if f.get("Commit") else ""
        rows.append((f["RuleID"], "high", "medium", rel, f.get("StartLine", 0),
                     f"[REDACTED] {f.get('Description', '')}{where}"))
    return rows, "ran", f"{len(rows)} findings ({'commit history' if mode == 'git' else 'working files'}); exit {p.returncode}"


def run_osv(root):
    """Known-vulnerable dependencies. Matches against downloaded public databases, so no
    package list or code from the repo leaves this Mac."""
    exe = shutil.which("osv-scanner")
    if not exe:
        return [], "not_run", "not installed"
    try:
        p = subprocess.run([exe, "scan", "source", "-r", "--offline-vulnerabilities", "--download-offline-databases",
                            "--format", "json", "--verbosity", "error", root],
                           capture_output=True, text=True, timeout=900)
        data = json.loads(p.stdout) if p.stdout.strip().startswith("{") else None
    except (subprocess.TimeoutExpired, OSError, ValueError) as e:
        return [], "failed", type(e).__name__
    if data is None:
        msg = (p.stderr or p.stdout).strip().splitlines()[-1:] or ["no output"]
        none = "no package sources found" in (p.stderr + p.stdout).lower()
        return [], "not_covered" if none else "failed", ("no lockfile that osv-scanner supports (deno.lock is not); "
                                                             "dependencies were NOT checked") if none else msg[0][:200]
    rows, manifests = [], 0
    for res in data.get("results", []):
        rel = os.path.relpath(res["source"]["path"], root)
        if _noise(rel):
            continue
        manifests += 1
        for pk in res.get("packages", []):
            name = f"{pk['package']['name']}@{pk['package'].get('version', '?')}"
            worst = {}
            for g in pk.get("groups", []):
                for i in g.get("ids", []):
                    worst[i] = g.get("max_severity", "")
            for v in pk.get("vulnerabilities", []):
                try:
                    score = float(worst.get(v["id"]) or 0)
                except ValueError:
                    score = 0
                sev = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score else "unknown"
                rows.append(("vulnerable-dependency", sev, "high", rel, 0, f"{name}: {v['id']} {v.get('summary', '')[:120]}"))
    return rows, "ran", f"{len(rows)} known vulnerabilities across {manifests} lockfiles with findings"
MAX_FILE = 1024 * 1024
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".mp4", ".mov", ".mp3", ".wav", ".pdf", ".zip", ".woff",
            ".woff2", ".ttf", ".ico", ".lock", ".map", ".bin", ".glb", ".psd"}


def remotes(repo):
    cp = configparser.ConfigParser(strict=False, interpolation=None)
    try:
        cp.read(os.path.join(repo, ".git", "config"))
    except configparser.Error:
        return []
    return [{"name": s.split('"')[1], "url": redact(cp[s].get("url", ""))} for s in cp.sections() if s.startswith('remote "')]


def audit(cfg, con, name):
    repo = cfg["repos"].get(name)
    if repo is None:
        raise PermissionError(f"repo '{name}' is not approved")
    root = repo["path"]
    if not os.path.isdir(root):
        return {"repo": name, "status": "unavailable", "detail": "path is not present on this Mac"}
    commit, ref = git_head(root)
    if commit:
        revision = f"{ref}@{commit}"
    elif os.path.exists(os.path.join(root, ".git")):
        revision = ".git exists but has no readable commit (empty repo, or its contents are not on this Mac)"
    else:
        revision = "not a git repo (working files only)"
    t = now()
    con.execute("delete from findings where repo=?", (name,))
    con.execute("delete from scans where repo=?", (name,))
    scanned = skipped = 0
    src = {"root": root, "kind": "local", "exclude": [".next", "dist", "build", "out", ".vercel", "vendor", "venv", "env", "site-packages"]}
    env_files = []
    for rel, path, size, _m, avail in adapters.walk(src):
        base = os.path.basename(rel)
        if base.startswith(".env") and not base.endswith((".example", ".sample", ".template")):
            env_files.append(rel)
        if avail != "readable" or size > MAX_FILE or os.path.splitext(rel)[1].lower() in SKIP_EXT:
            skipped += 1
            continue
        try:
            with open(path, "rb") as fh:
                text = fh.read()
        except OSError:
            skipped += 1
            continue
        if b"\x00" in text:
            skipped += 1
            continue
        scanned += 1
        text = text.decode("utf-8", errors="replace")
        for rule, severity, pat in RULES:
            for m in pat.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                is_test = any(x in rel.lower() for x in ("test", "fixture", "example", "sample", "mock"))
                con.execute(
                    "insert into findings(repo,revision,scanner,rule,severity,confidence,path,line,evidence,created_at)"
                    " values(?,?,?,?,?,?,?,?,?,?)",
                    (name, revision, "lucy-patterns", rule, severity, "low" if is_test or rule == "assigned-secret" else "medium",
                     rel, line, f"[REDACTED:{rule}] ({len(m.group(0))} chars)", t))
    ignore = ""
    try:
        ignore = open(os.path.join(root, ".gitignore")).read()
    except OSError:
        pass
    for rel in env_files:
        if ".env" not in ignore:
            con.execute(
                "insert into findings(repo,revision,scanner,rule,severity,confidence,path,line,evidence,created_at)"
                " values(?,?,?,?,?,?,?,?,?,?)",
                (name, revision, "lucy-patterns", "env-file-not-ignored", "high", "medium", rel, 0,
                 ".env file present and .gitignore has no .env rule; check whether it was ever committed", t))

    def cover(scanner, status, detail):
        con.execute("insert into scans(repo,revision,scanner,status,detail,created_at) values(?,?,?,?,?,?)",
                    (name, revision, scanner, status, detail, t))

    cover("lucy-patterns", "ran", f"{scanned} text files read, {skipped} skipped (binary, large or cloud-only); "
          "working tree only, no git history")
    def store(scanner, rows):
        for rule, sev, conf, rel, line, ev in rows:
            con.execute(
                "insert into findings(repo,revision,scanner,rule,severity,confidence,path,line,evidence,created_at)"
                " values(?,?,?,?,?,?,?,?,?,?)", (name, revision, scanner, rule, sev, conf, rel, line, ev, t))

    rows, status, detail = run_gitleaks(root, "dir")
    store("gitleaks", rows)
    cover("gitleaks (working files)", status, detail)
    if commit:
        rows, status, detail = run_gitleaks(root, "git")
        store("gitleaks-history", rows)
        cover("gitleaks (git history)", status, detail)
    else:
        cover("gitleaks (git history)", "not_run", "no readable git history on this Mac")
    rows, status, detail = run_osv(root)
    store("osv-scanner", rows)
    cover("osv-scanner", status, detail)
    for tool, what in EXTERNAL.items():
        cover(tool, "not_run", f"{what}: " + ("installed but not wired up yet" if shutil.which(tool) else "not installed"))
    cover("manual-review", "not_done", "auth, database row-level security, uploads, webhooks, CI permissions, "
          "storage exposure, API abuse, prompt injection")
    con.commit()
    n = con.execute("select count(*) from findings where repo=?", (name,)).fetchone()[0]
    log("repo_audit", repo=name, findings=n, files=scanned)
    return {"repo": name, "revision": revision, "remotes": remotes(root), "files_read": scanned,
            "findings": n, "note": "Zero findings would not mean secure. See coverage."}


def findings(cfg, con, repo=None):
    names = [n for n in cfg["repos"] if repo is None or n == repo]
    out = {"findings": [], "coverage": []}
    for n in names:
        out["findings"] += [dict(r) for r in con.execute(
            "select repo,revision,scanner,rule,severity,confidence,path,line,evidence from findings where repo=? "
            "order by case severity when 'critical' then 0 when 'high' then 1 else 2 end, path limit 300", (n,))]
        out["coverage"] += [dict(r) for r in con.execute(
            "select repo,scanner,status,detail,created_at from scans where repo=?", (n,))]
    never = [n for n in names if not any(c["repo"] == n for c in out["coverage"])]
    out["never_scanned"] = never
    return out
