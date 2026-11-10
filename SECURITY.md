# Security

Lucy sits between AI tools and your files, so reports about it are taken seriously.

## Reporting a problem

Use GitHub's private reporting: the **Security** tab of this repository, then **Report a vulnerability**.
Please do not open a public issue for something that lets a tool read outside an approved folder,
leak a secret through an excerpt, or write when writes are off.

Include the command or MCP call, what you expected and what happened. A failing test in the style of
`tests/test_acceptance.py` is the best report there is.

## What counts

- Reading or listing anything outside an approved source: traversal, symlinks, excluded subfolders, another project's files.
- A secret that survives redaction in an excerpt, a finding or the audit log.
- Any write through MCP while `mcp_writes` is off.
- Any network call from Lucy's own code.
- A scan that marks files as gone because a drive or synced folder was missing.

## What Lucy does not claim

It does not encrypt anything, it is not a malware scanner, and it does not sandbox the assistant
that calls it. The threat model is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
