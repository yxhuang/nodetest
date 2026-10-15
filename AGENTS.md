# AGENTS.md

nodetest: a small tool that starts a private mihomo instance, reads proxy nodes from the local proxy client's generated config, and measures each node's latency, handshake, stability and download bandwidth through its own local port. It never changes the selection of the user's running proxy client.

If `HANDOFF.md` exists at the repository root (a local, untracked file), read it first: it holds the maintainer's current state, decisions and open tasks.

## Hard rules

- Never send test traffic to Claude / Anthropic domains, and never change the running proxy client's selected node or config (only read-only calls to its controller).
- Proxy credentials are read from the local machine at run time only. Never commit, log or print server addresses, passwords, UUIDs or controller secrets. Temporary configs live in a private directory with restrictive permissions and are removed on exit.
- This repository is public: no personal paths, usernames, hostnames or tailnet names in tracked files.
