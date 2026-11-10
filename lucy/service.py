"""One place that assembles a project's context, shared by the CLI and the MCP server."""
from . import catalog, handoff, records, security


def project_context(cfg, con, project):
    recs = records.latest(con, project)
    by_kind = {}
    for r in recs:
        by_kind.setdefault(r["kind"], []).append(
            {"key": r["key"], "rev": r["rev"], "body": r["body"], "author": r["author"],
             "source": r["source"], "confidence": r["confidence"], "at": r["created_at"]})
    return {
        "project": project,
        "sources": catalog.source_status(cfg, con, project),
        "records": by_kind,
        "unresolved_write_conflicts": records.conflicts(con, project),
        "handoffs": handoff.list_all(cfg, project),
        "content_conflicts_same_path": len(catalog.conflicts(cfg, con, project)),
        "note": "Records are what was explicitly saved to Lucy. Lucy cannot see an assistant's private memory.",
    }


def security_findings(cfg, con, repo=None):
    return security.findings(cfg, con, repo)
