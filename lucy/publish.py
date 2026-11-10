"""Publish gate: finds working-notes language in files that are about to go public.

This is what let an "Explorations · None is final" design section ship on a live launch page.
Pattern matching cannot know intent, so every hit is a question for the owner, not a verdict,
and a clean result is not approval. Reads working files only, from approved repos."""
import os
import re

from . import adapters
from .redact import log

TEXT_EXT = {".html", ".htm", ".md", ".mdx", ".txt", ".js", ".ts", ".jsx", ".tsx", ".css", ".json", ".svelte",
            ".vue", ".astro", ".xml", ".svg", ".yml", ".yaml", ".toml", ".py", ".rb", ".go", ".rs", ".swift"}
MAX_FILE = 1024 * 1024
# Default excludes. Tests and fixtures are never published; docs that are about the project are.
EXCLUDE = [".git", "node_modules", ".next", "dist", "build", "out", ".vercel", "vendor", "venv", "env",
           "site-packages", "tests", "test", "__tests__", "fixtures", "shots", "screenshots"]
EXCLUDE_FILES = {"readme.md", "status.md", "launch_status.md", "changelog.md", "license", "notice", "security.md"}

# (rule, severity, pattern). Severity is how sure we are this is working text, not product text.
RULES = [
    ("exploration", "high", re.compile(r"\b(explorations?|none (is|are) final|not final|which (one|do you like)|option [a-c]\b|variant \d|direction \d)", re.I)),
    ("draft", "high", re.compile(r"\b(draft|wip|work in progress|coming soon|under construction|placeholder|lorem ipsum|tbd|tk\b|xxx)\b", re.I)),
    ("internal-note", "high", re.compile(r"\b(todo|fixme|hack|internal( only)?|do not (ship|publish)|remove (this|before)|before launch|pre-launch|not connected|backend not connected|mock(ed)?|stub(bed)?|fake)\b", re.I)),
    ("ai-attribution", "high", re.compile(r"(co-authored-by|generated (with|by)|built with (claude|chatgpt|gpt|copilot|cursor|ai)\b|🤖)", re.I)),
    ("handoff-voice", "medium", re.compile(r"\b(live on this page|on this page we|we('re| are) (still|not yet)|needs? (his|her|their|your) (⭐|pick|decision)|for review|review copy)\b", re.I)),
    ("real-name-or-path", "medium", re.compile(r"(/Users/[a-z0-9_.-]+/|~/Projects/|Dropbox/00_COMMAND_CENTER|C:\\Users\\)", re.I)),
    ("secret-shaped", "high", re.compile(r"\b(sk-[A-Za-z0-9]{16,}|re_[A-Za-z0-9]{16,}|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,})", 0)),
]
# Words that are product copy when they appear as a visible label; keep them but mark them so the owner looks.
ALLOWED_IF_LABEL = {"draft", "example output", "mock"}


def _skip(rel, exclude):
    parts = rel.lower().split("/")
    return any(p in exclude for p in parts[:-1]) or parts[-1] in EXCLUDE_FILES


def check(cfg, con, name, include_docs=False):
    repo = cfg["repos"].get(name)
    if repo is None:
        raise PermissionError(f"repo '{name}' is not approved")
    root = repo["path"]
    if not os.path.isdir(root):
        return {"repo": name, "status": "unavailable", "detail": "path is not present on this Mac"}
    exclude = [e for e in EXCLUDE]
    src = {"root": root, "kind": "local", "exclude": exclude}
    hits, scanned, skipped = [], 0, 0
    for rel, path, size, _m, avail in adapters.walk(src):
        if _skip(rel, exclude) and not include_docs:
            skipped += 1
            continue
        if avail != "readable" or size > MAX_FILE or os.path.splitext(rel)[1].lower() not in TEXT_EXT:
            skipped += 1
            continue
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
        except OSError:
            skipped += 1
            continue
        if b"\x00" in raw:
            skipped += 1
            continue
        scanned += 1
        text = raw.decode("utf-8", errors="replace")
        for rule, severity, pat in RULES:
            for m in pat.finditer(text):
                line_no = text.count("\n", 0, m.start()) + 1
                line = text.splitlines()[line_no - 1].strip()
                word = m.group(0).lower()
                if word == "placeholder" and os.path.splitext(rel)[1].lower() in {".js", ".ts", ".jsx", ".tsx", ".css"}:
                    continue  # in script and style files this is the DOM attribute, not copy
                if word == "placeholder" and ("placeholder=" in line or "placeholder {" in line or ".placeholder" in line or "::placeholder" in line or "target.placeholder" in line):
                    continue  # the HTML attribute / CSS pseudo-element, not a placeholder in the copy
                sev = "medium" if (rule == "draft" and word in ALLOWED_IF_LABEL) or word in ("not connected",) else severity
                ev = m.group(0) if rule != "secret-shaped" else f"[REDACTED:{rule}] ({len(m.group(0))} chars)"
                hits.append({"rule": rule, "severity": sev, "path": rel, "line": line_no, "match": ev,
                             "context": line[:160] if rule != "secret-shaped" else ""})
    hits.sort(key=lambda h: ({"high": 0, "medium": 1}.get(h["severity"], 2), h["path"], h["line"]))
    verdict = "hold" if any(h["severity"] == "high" for h in hits) else "ask" if hits else "no-hits"
    log("publish_check", repo=name, hits=len(hits), files=scanned)
    return {"repo": name, "verdict": verdict, "files_read": scanned, "files_skipped": skipped, "hits": hits,
            "note": "Every hit is a question for the owner. 'no-hits' is not approval; read the page as a stranger would."}
