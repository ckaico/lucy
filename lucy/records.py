"""Attributed, versioned project records. Writes need the revision they were based on."""
from . import config
from .redact import log, now

KINDS = ("decision", "fact", "proposal", "inference", "task", "blocker", "note")


class StaleWrite(Exception):
    pass


def put(cfg, con, project, key, kind, body, author, source="", confidence="", expected_rev=0):
    if project not in config.projects(cfg):
        raise PermissionError(f"project '{project}' has no approved source")
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {KINDS}")
    con.execute("begin immediate")
    cur = con.execute("select coalesce(max(rev),0) from records where project=? and key=?", (project, key)).fetchone()[0]
    if int(expected_rev) != cur:
        # Reject, but keep the rejected text so an offline edit is never silently lost.
        con.execute("insert into rejected_writes(project,key,expected_rev,actual_rev,kind,body,author,created_at)"
                    " values(?,?,?,?,?,?,?,?)", (project, key, expected_rev, cur, kind, body, author, now()))
        con.commit()
        log("record_rejected", project=project, key=key, expected_rev=expected_rev, actual_rev=cur)
        raise StaleWrite(f"'{key}' is at revision {cur}, you wrote against {expected_rev}. "
                         "Your text was kept as a conflict; read the current revision and decide.")
    con.execute("insert into records values(?,?,?,?,?,?,?,?,?)",
                (project, key, cur + 1, kind, body, author, source, confidence, now()))
    con.commit()
    log("record_saved", project=project, key=key, rev=cur + 1, kind=kind, author=author)
    return {"project": project, "key": key, "rev": cur + 1}


def history(con, project, key):
    return [dict(r) for r in con.execute("select * from records where project=? and key=? order by rev", (project, key))]


def latest(con, project):
    rows = con.execute(
        "select r.* from records r join (select key, max(rev) m from records where project=? group by key) x"
        " on r.key=x.key and r.rev=x.m where r.project=? order by r.kind, r.key", (project, project))
    return [dict(r) for r in rows]


def conflicts(con, project):
    return [dict(r) for r in con.execute("select * from rejected_writes where project=? order by id", (project,))]
