# Architecture, data model and threat model

## Shape

```
Claude Code ──stdio──> lucy mcp ─┐
you ──────────────────> bin/lucy ┼─> access.py (deny by default) ─> approved folders (read only)
                                 └─> ~/.lucy: config.json, catalog.db, handoffs/, snapshots/, store/, audit.log
```

Everything is local. Lucy has no network code and calls no model. The model reasoning comes
from whatever assistant is calling the MCP tools.

| Module | Job |
|---|---|
| `config.py` | Approved sources, projects, repos. The only authority for permissions. |
| `access.py` | Path checks and bounded reads. Every read goes through `resolve()`. |
| `adapters.py` | Is the source there (RAID by volume identity), is each file local or a placeholder. |
| `catalog.py` | Scan, search, versions, conflicts, duplicates, revoke. |
| `records.py` | Versioned decisions, facts, tasks, blockers. |
| `handoff.py` | Handoff manifests and live validation. |
| `snapshot.py` | Content-addressed copies with verify and restore. |
| `security.py` | Read-only repo baseline and coverage record. |
| `redact.py` | Secret patterns, redaction, audit log. |

## Data model

- **Source**: one approved folder. Has a kind (dropbox, icloud, raid, local), a project, a device,
  optional excludes and, for a RAID, a volume identity.
- **Logical asset**: a project plus a path or file name.
- **Copy**: one observation of an asset in one source: size, modified time, availability,
  SHA-256 when the content was read, first and last seen. Copies are never deleted by a scan;
  a file that disappears is flagged, and its row stays.
- **Copy history**: each new content hash seen at a copy. This is the ancestry evidence. If copy A
  once held the content copy B holds now, A is newer. Modified time is displayed, never used to
  pick a winner. With no history, Lucy says "divergent" and leaves the choice to you.
- **Record**: project, key, revision, kind, body, author, source, confidence. A write must name
  the revision it was based on. A stale write is rejected and its text kept in `rejected_writes`.
- **Handoff**: summary, decisions, unfinished work, blockers, next steps, and required files with
  the hash pinned at creation.

File status words used in handoff checks: `present`, `changed`, `intentionally_excluded`,
`remote` (on another device), `source_offline`, `not_downloaded` (cloud placeholder),
`access_denied`, `not_found` (in the sources checked), `never_checked`.

## Permission model

- Deny by default. A path is readable only inside an approved, non-revoked source.
- A request scoped to a project cannot reach another project's source.
- Paths must be relative, with no `..`. The resolved real path must stay inside the source root,
  which blocks symlink escapes. Scans never follow symlinks.
- Reads are bounded (8,000 bytes per call by default), text only, with secret patterns redacted.
- Reads and writes are separate. MCP writes are off unless `mcp_writes` is true. Writes only
  ever land in `~/.lucy`. Lucy never writes into Dropbox, iCloud or the RAID.
- Restore only writes into a new or empty folder.
- No tool runs a shell command, SQL, a URL fetch or a general file read.
- Revocation is checked on every call. Revoking deletes that source's catalog rows and history.
  Snapshots already taken are kept and listed, and are removed by hand.

## Threat model

| Threat | What Lucy does | What is left |
|---|---|---|
| A document tells the assistant to widen access or run something | Content is returned as data, flagged untrusted. No tool can change permissions or execute. Config changes need the CLI. | The calling assistant could still be misled into misusing its *other* tools. Lucy cannot control those. |
| Path traversal, symlink escape, cross-project reads | Blocked in `access.resolve`, tested. | A source approved too broadly exposes everything in it. Keep roots narrow. |
| Secrets leaking through excerpts, logs or handoffs | Pattern redaction on excerpts, audit log, handoffs, findings. | Pattern matching misses unusual secrets. Not a guarantee. |
| Unplugged RAID or unsynced folder read as deletion | Volume identity check; absent or empty roots never mark files gone. | A folder that syncs down partly empty looks like real deletions. Copies are flagged, not removed. |
| Reading a cloud placeholder triggers a download | Placeholders are detected from flags, names and attributes and never opened. | Detection relies on macOS and Dropbox conventions that can change. |
| Someone with access to this Mac reads `~/.lucy` | Folder is owner-only (0700). | See encryption below. |

## Encryption and data handling

Stated plainly, since the spec asked for no overclaiming:

- `~/.lucy` is **plaintext** on the Mac's internal disk. The catalog holds paths, sizes and
  hashes. Snapshots hold full file copies. Records and handoffs hold your text.
- That disk has FileVault on, which protects a powered-off, stolen Mac. It does not protect
  against anyone or anything running as your user. This is **not** end-to-end encryption.
- Lucy sends nothing off the machine. When an assistant calls a Lucy tool, the result goes to
  that assistant's model service like any other tool output. That is the one outbound path,
  and it carries only what the tool returned.
- No remote storage exists yet. Before any does, these must be decided: who holds the keys, who
  can decrypt, recovery if a key is lost, retention, deletion, and whether metadata (file names,
  hashes) is protected too.
- The RAID's redundancy protects against a failed drive. It is not a second copy elsewhere.
