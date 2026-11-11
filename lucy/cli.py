import argparse
import getpass
import json
import os
import sys

from . import access, catalog, config, content, db, handoff, publish, records, security, service, snapshot
from .redact import log


def _file_ref(s):
    sid, _, path = s.partition(":")
    return {"source": sid, "path": path}


def build():
    p = argparse.ArgumentParser(prog="lucy", description="Project memory, storage catalog and security bridge.")
    sub = p.add_subparsers(dest="cmd", required=True)

    def cmd(name, **kw):
        return sub.add_parser(name, **kw)

    s = cmd("source-add", help="approve a folder as a source")
    s.add_argument("id"); s.add_argument("--kind", required=True, choices=config.KINDS)
    s.add_argument("--root", required=True); s.add_argument("--project", required=True)
    s.add_argument("--volume-uuid"); s.add_argument("--device"); s.add_argument("--exclude", action="append", default=[])
    cmd("sources", help="live status of every approved source").add_argument("--project")
    cmd("source-revoke").add_argument("id")
    cmd("scan", help="refresh the catalog").add_argument("ids", nargs="*")
    cmd("projects")
    s = cmd("search"); s.add_argument("query"); s.add_argument("--project")
    s = cmd("search-text", help="find files by what they say"); s.add_argument("query"); s.add_argument("--project")
    s = cmd("versions", help="every copy of one file, grouped by content"); s.add_argument("project"); s.add_argument("name")
    s = cmd("conflicts"); s.add_argument("--project"); s.add_argument("--by-name", action="store_true")
    cmd("duplicates").add_argument("--project")
    s = cmd("read"); s.add_argument("source"); s.add_argument("path"); s.add_argument("--offset", type=int, default=0)
    cmd("context").add_argument("project")
    s = cmd("note", help="save a versioned record")
    s.add_argument("project"); s.add_argument("key"); s.add_argument("body")
    s.add_argument("--kind", default="note", choices=records.KINDS); s.add_argument("--author", default=getpass.getuser())
    s.add_argument("--source", default=""); s.add_argument("--confidence", default="")
    s.add_argument("--expected-rev", type=int, default=0)
    s = cmd("note-history"); s.add_argument("project"); s.add_argument("key")
    s = cmd("handoff-create")
    s.add_argument("project"); s.add_argument("title"); s.add_argument("--author", default=getpass.getuser())
    s.add_argument("--summary", default="")
    for name in ("decision", "unfinished", "blocker", "next"):
        s.add_argument(f"--{name}", action="append", default=[])
    s.add_argument("--file", action="append", default=[], help="source:relative/path")
    s.add_argument("--exclude", action="append", default=[], help="path=reason")
    cmd("handoffs").add_argument("--project")
    cmd("handoff-validate").add_argument("id")
    s = cmd("handoff-check-refs", help="check every file an existing document mentions")
    s.add_argument("source"); s.add_argument("path")
    s = cmd("snapshot"); s.add_argument("source"); s.add_argument("--prefix", default="")
    cmd("snapshot-verify").add_argument("id")
    s = cmd("restore"); s.add_argument("id"); s.add_argument("dest")
    s = cmd("repo-add"); s.add_argument("name"); s.add_argument("path")
    cmd("repo-audit").add_argument("names", nargs="*")
    cmd("findings").add_argument("--repo")
    pc = cmd("publish-check", help="flag working-notes language in files about to go public")
    pc.add_argument("names", nargs="*"); pc.add_argument("--include-docs", action="store_true")
    cmd("mcp", help="run the MCP server on stdio")
    return p


def run(a):
    cfg, con = config.load(), db.connect()
    c = a.cmd
    if c == "source-add":
        return access.add_source(cfg, a.id, a.kind, a.root, a.project, a.volume_uuid, a.device, a.exclude)
    if c == "sources":
        return catalog.source_status(cfg, con, a.project)
    if c == "source-revoke":
        return catalog.revoke(cfg, con, a.id)
    if c == "scan":
        return [catalog.scan(cfg, con, sid) for sid in (a.ids or config.project_sources(cfg))]
    if c == "projects":
        return [{"project": p, "sources": list(config.project_sources(cfg, p))} for p in config.projects(cfg)]
    if c == "search":
        return catalog.search(cfg, con, a.query, a.project)
    if c == "search-text":
        return content.search(cfg, con, a.query, a.project)
    if c == "versions":
        return catalog.versions(cfg, con, a.project, a.name)
    if c == "conflicts":
        return catalog.conflicts(cfg, con, a.project, a.by_name)
    if c == "duplicates":
        return catalog.duplicates(cfg, con, a.project)
    if c == "read":
        return access.read_excerpt(cfg, a.source, a.path, offset=a.offset)
    if c == "context":
        return service.project_context(cfg, con, a.project)
    if c == "note":
        return records.put(cfg, con, a.project, a.key, a.kind, a.body, a.author, a.source, a.confidence, a.expected_rev)
    if c == "note-history":
        return records.history(con, a.project, a.key)
    if c == "handoff-create":
        excl = [{"path": e.partition("=")[0], "reason": e.partition("=")[2]} for e in a.exclude]
        return handoff.create(cfg, con, a.project, a.title, a.author, a.summary, a.decision, a.unfinished,
                              a.blocker, a.next, [_file_ref(f) for f in a.file], excl)
    if c == "handoffs":
        return handoff.list_all(cfg, a.project)
    if c == "handoff-validate":
        return handoff.validate(cfg, con, a.id)
    if c == "handoff-check-refs":
        return handoff.check_refs(cfg, con, a.source, a.path)
    if c == "snapshot":
        return snapshot.create(cfg, con, a.source, a.prefix)
    if c == "snapshot-verify":
        return snapshot.verify(a.id)
    if c == "restore":
        return snapshot.restore(a.id, a.dest)
    if c == "repo-add":
        path = os.path.abspath(os.path.expanduser(a.path))
        cfg["repos"][a.name] = {"path": path}
        config.save(cfg)
        return cfg["repos"][a.name]
    if c == "repo-audit":
        return [security.audit(cfg, con, n) for n in (a.names or cfg["repos"])]
    if c == "findings":
        return security.findings(cfg, con, a.repo)
    if c == "publish-check":
        return [publish.check(cfg, con, n, a.include_docs) for n in (a.names or cfg["repos"])]


def main(argv=None):
    a = build().parse_args(argv)
    if a.cmd == "mcp":
        from . import mcp_server
        return mcp_server.main()
    try:
        out = run(a)
    except (access.Denied, PermissionError, records.StaleWrite, FileNotFoundError, ValueError) as e:
        log("cli_refused", cmd=a.cmd, error=str(e))
        print(json.dumps({"error": type(e).__name__, "detail": str(e)}, indent=2))
        return 1
    print(json.dumps(out, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
