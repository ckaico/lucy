# Status

Version 0.1. Local only, macOS only. Built and tested on one machine.

## Works

- Catalog of approved folders in Dropbox, iCloud Drive and an external volume (pinned by volume identity).
- Placeholder detection without reading or downloading content.
- Identical and differing copies; ancestry from observed history, never from dates.
- Handoff manifests with pinned hashes and live validation; reference check of existing documents.
- Versioned project records with expected-revision writes.
- Snapshots into a local content-addressed store, with verify and restore.
- Read-only repo baseline: built-in patterns, plus gitleaks and osv-scanner when installed.
- Publish gate (`publish-check`, MCP `check_publish_ready`): working-notes language in files about to go public.
- CLI and MCP server (stdio). MCP writes are off by default.
- Full-text index of readable text files (SQLite FTS5, BM25, stemming); background rescan of stale sources from the MCP server.

## Tested

`tests/test_acceptance.py`, 22 tests on throwaway fixtures: three-source search, differing and
identical copies, placeholders, volume disconnect, empty synced folder, stale writes, missing handoff
files, traversal and symlink escape, cross-project access, instructions inside documents, secret
redaction, revocation, no network code, an MCP client round trip, snapshot restore, publish gate,
full-text search (stemming, project scope, redacted excerpts, removed and revoked files dropped), auto-scan staleness.

Not covered by automated tests: a physically unplugged volume, and a live modern iCloud placeholder.

## Missing

- Dropbox API connector (file IDs, revisions, change cursors). Today Lucy sees only the local folder.
- Sharing one catalog between machines.
- Per-file git commit tracking.
- Encrypted or off-machine storage. Snapshots are local plaintext copies.
- Remote access. There is no network endpoint, by design.
- Security advisory monitoring.
