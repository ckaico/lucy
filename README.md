<p align="center"><img src="docs/logo.svg" width="80" alt="Lucy"></p>

<h1 align="center">Lucy</h1>

<p align="center"><b>Give your AI the file. Not the drive.</b><br>
<a href="https://lucy.so">lucy.so</a> · Apache 2.0 · local only · no account, no API key</p>

Your work lives in Dropbox, iCloud Drive and on a drive under the desk. Your AI tools get wired
into all of it, with full access, and none of them can tell you which copy of a file is the current one.

Lucy is a small local server that fixes both problems:

- **One index.** It maps every folder you approve, fingerprints each file with SHA-256 and tells
  you which copies match, which differ and which are only a cloud placeholder that was never downloaded.
- **One gate.** Claude Code, Codex or any MCP client asks Lucy for a file. Lucy answers with a short
  excerpt, secrets masked, from approved folders only. Every request is logged, allowed or denied.

It moves nothing, deletes nothing, downloads nothing and makes no network calls.

## Install

Needs macOS, Python 3.11 or newer and [`uv`](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/ckaico/lucy && cd lucy
uv sync
claude mcp add --scope user lucy -- "$PWD/bin/lucy" mcp
```

Any other MCP client: run `bin/lucy mcp` over stdio. For Codex, in `~/.codex/config.toml`:

```toml
[mcp_servers.lucy]
command = "/path/to/lucy/bin/lucy"
args = ["mcp"]
```

Lucy keeps its config, catalog and log in `~/.lucy` (set `LUCY_HOME` to move it).

## Approve a folder

Nothing is readable until you approve it. A source is one folder, tied to one project.

```bash
bin/lucy source-add film-dropbox --kind dropbox --root ~/Dropbox/Film --project film --exclude private
bin/lucy source-add film-icloud  --kind icloud  --root ~/Library/Mobile\ Documents/com~apple~CloudDocs/Film --project film
bin/lucy source-add film-raid    --kind raid    --root /Volumes/MY_RAID/Film --project film
bin/lucy scan
```

`--exclude` keeps a subfolder out of the index and blocks reads of it. A `raid` source is pinned to
the volume's identity, so a different drive mounted at the same path is not trusted. If a drive is
unplugged, Lucy says so. It never concludes your files are gone.

## Which copy is current?

```bash
bin/lucy versions film HANDOFF.md
```

```json
{
  "asset": "HANDOFF.md",
  "copies": 3,
  "verdict": "divergent: no history proves which is current; needs your decision",
  "versions": [
    { "sha256": "64550b1c…", "copies": [ { "source": "film-raid" }, { "source": "film-dropbox" } ] },
    { "sha256": "a3a0fab0…", "copies": [ { "source": "film-icloud" } ] }
  ]
}
```

(Output shortened.) Two copies match, one differs. Lucy will not pick a winner from modified dates,
because dates lie across sync services. It names a newer version only when it has watched one replace the other.

## What an assistant can and cannot do

| | |
|---|---|
| allow | search and list files in approved folders, one project at a time |
| allow | short text excerpts with secrets masked |
| allow | check that a handoff's files exist and are unchanged |
| deny | any path that leaves an approved folder, symlinks included |
| deny | shell, SQL, URL fetch, general file read |
| deny | instructions found inside a document: file text is returned as data, never obeyed |
| deny | writes, until you set `"mcp_writes": true` in `~/.lucy/config.json` |

```bash
$ bin/lucy read film-dropbox ../../.ssh/id_ed25519
{ "error": "Denied", "detail": "path must be relative to the source root, with no '..'" }
```

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
| Check my repos for leaked keys | `bin/lucy repo-add name path`, `bin/lucy repo-audit`, `bin/lucy findings` |
| Is this safe to make public? | `bin/lucy publish-check <repo>` |

`repo-audit` uses gitleaks and osv-scanner when they are installed, and reports which checks did not run.

## What it does not do

- No encryption. Snapshots are plain local copies. Encrypted backups with keys you hold are planned.
- No malware scanning.
- No Dropbox, iCloud or Google Drive API. Lucy sees the folders synced to this Mac.
- No sharing between machines yet, and no remote access. There is no network endpoint.
- macOS only.

The full list, with what is tested and what is not: [docs/STATUS.md](docs/STATUS.md).
How it is built and what it defends against: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Where it is going

1. **Now: one index.** Your files stay where they are. Lucy maps them and guards the door.
2. **Next: one network.** Every Mac you own in one view, Google Drive, a live board for every project, encrypted backups.
3. **Later: one server.** Your clouds and drives as one pool, with a database and logins for the apps you build.

Only the first is built. Early access to the rest: [lucy.so](https://lucy.so).

## Tests

```bash
.venv/bin/python -m unittest tests.test_acceptance -v
```

19 tests on throwaway folders: traversal and symlink escape, cross-project access, instructions hidden
in documents, secret redaction, revoked sources, a disconnected drive, stale writes, and a check
that Lucy's own code contains no network calls.

## Security

Found a way past the gate? See [SECURITY.md](SECURITY.md).

## Licence

Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). © 2026 Christian Kai (CKAI).
