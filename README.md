# Lucy

Lucy keeps one catalog of your project files across Dropbox, iCloud Drive and an external RAID.
It tells you which copy is where, whether the content is really on this Mac, whether copies
match, and whether a handoff has all its files. It runs locally and needs no model API.

What works, what is tested and what is missing: [docs/STATUS.md](docs/STATUS.md).
How it is built and what it protects against: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Setup

Needs macOS, Python 3.11+ and `uv`.

```bash
cd ~/Projects/lucy
uv sync
bin/lucy projects
```

Lucy keeps its config, catalog, handoffs and snapshots in `~/.lucy` (set `LUCY_HOME` to move it).

## Approve sources

Nothing is readable until you approve it. Each source is one folder, tied to one project.

```bash
bin/lucy source-add film-raid --kind raid --root /Volumes/MY_RAID/Film --project film
bin/lucy source-add film-dropbox --kind dropbox --root ~/Dropbox/Film --project film --exclude private
bin/lucy source-add film-icloud --kind icloud --root ~/Library/Mobile\ Documents/com~apple~CloudDocs/Film --project film
bin/lucy scan
bin/lucy sources
```

A `raid` source is pinned to the volume's identity, not only its path. `--exclude` keeps a
subfolder out of the catalog and blocks reads of it. `--device air` declares a source that
lives on another Mac; Lucy reports it as remote instead of missing.

## Everyday commands

| Question | Command |
|---|---|
| Where is this file? | `bin/lucy search HANDOFF --project film` |
| Which copy is current? | `bin/lucy versions film STATUS.md` |
| What differs between sources? | `bin/lucy conflicts --project film` |
| Is this handoff complete? | `bin/lucy handoff-validate <id>` |
| Does this old handoff doc point at real files? | `bin/lucy handoff-check-refs film-dropbox path/to/HANDOFF.md` |
| What do we know about a project? | `bin/lucy context film` |
| Save a decision | `bin/lucy note film launch-date "Ship Friday" --kind decision --expected-rev 0` |
| Copy a folder somewhere safe | `bin/lucy snapshot film-icloud`, then `snapshot-verify` and `restore <id> <new folder>` |
| Check repos | `bin/lucy repo-add name path`, `bin/lucy repo-audit`, `bin/lucy findings` |
| Is this safe to make public? | `bin/lucy publish-check <repo>` flags explorations, drafts, TODOs, "before launch", local paths, AI attribution. `hold` means read every hit first. |

## Claude Code

```bash
claude mcp add --scope user lucy -- ~/Projects/lucy/bin/lucy mcp
```

Read tools are always on. The two write tools (`save_note`, `save_handoff`) stay off until you
set `"mcp_writes": true` in `~/.lucy/config.json`.

## Tests

```bash
.venv/bin/python -m unittest tests.test_acceptance -v
```

## Licence

Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
