"""Full-text index of readable text files, so a session can find a file by what it says,
not only by its name. Ranked (BM25) with stemming. Lives in the local catalog only.
Placeholders are never downloaded to be indexed; excluded folders are never walked."""
import os
import re

from . import config
from .redact import redact

TEXT_EXT = {
    ".md", ".markdown", ".txt", ".rtf", ".csv", ".tsv", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg",
    ".py", ".js", ".mjs", ".ts", ".tsx", ".jsx", ".html", ".htm", ".css", ".scss", ".swift", ".kt", ".java",
    ".go", ".rs", ".rb", ".php", ".sh", ".zsh", ".sql", ".xml", ".srt", ".vtt", ".fountain", ".tex", ".org",
}
MAX_BYTES = 1024 * 1024


def indexable(rel, size):
    return os.path.splitext(rel)[1].lower() in TEXT_EXT and 0 < size <= MAX_BYTES


def update(con, sid, rel, path, sha):
    """Index one file if its content changed since it was last indexed."""
    row = con.execute("select id, sha256 from content_meta where source_id=? and relpath=?", (sid, rel)).fetchone()
    if row and row["sha256"] == sha:
        return False
    try:
        with open(path, "rb") as f:
            body = f.read(MAX_BYTES).decode("utf-8", errors="replace")
    except OSError:
        return False
    if row:
        con.execute("delete from content_fts where rowid=?", (row["id"],))
        con.execute("update content_meta set sha256=? where id=?", (sha, row["id"]))
        rid = row["id"]
    else:
        rid = con.execute("insert into content_meta(source_id, relpath, sha256) values(?,?,?)", (sid, rel, sha)).lastrowid
    con.execute("insert into content_fts(rowid, path, body) values(?,?,?)", (rid, rel.replace("/", " "), body))
    return True


def drop(con, sid, only_gone=False):
    """Remove index entries for a whole source, or only for its files that are gone."""
    q = "select id from content_meta where source_id=?"
    if only_gone:
        q += " and relpath in (select relpath from copies where source_id=? and gone=1)"
    ids = [r["id"] for r in con.execute(q, (sid, sid) if only_gone else (sid,))]
    for i in ids:
        con.execute("delete from content_fts where rowid=?", (i,))
        con.execute("delete from content_meta where id=?", (i,))
    return len(ids)


def _match(query):
    terms = re.findall(r"\w+", query.lower())
    return " OR ".join(f'"{t}"' for t in terms) if terms else None


def search(cfg, con, query, project=None, limit=20):
    sids = list(config.project_sources(cfg, project))
    m = _match(query)
    if not sids or not m:
        return []
    marks = ",".join("?" * len(sids))
    rows = con.execute(
        "select m.source_id, m.relpath, snippet(content_fts, 1, '[', ']', ' … ', 16) snip, bm25(content_fts) score "
        f"from content_fts join content_meta m on m.id = content_fts.rowid "
        f"where content_fts match ? and m.source_id in ({marks}) order by score limit ?",
        (m, *sids, min(int(limit), 100))).fetchall()
    return [{"source": r["source_id"], "project": cfg["sources"][r["source_id"]]["project"], "path": r["relpath"],
             "excerpt": redact(r["snip"])} for r in rows]
