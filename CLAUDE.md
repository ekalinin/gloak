# CLAUDE.md

The working conventions for this repository live in **[AGENTS.md](AGENTS.md)**. Read
that file; it applies in full here.

It is kept in one place on purpose. Duplicating the rules into a second file means
they drift, and the copy that drifts is always the one somebody is following.

Two points from it are worth repeating, because they are the ones most easily
skipped:

- **Observable values are measured against a live Keycloak 26.7.1, never written
  from memory.** The measured contract is
  `docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md`.
- **Several of Keycloak's behaviours look like bugs and are not.** AGENTS.md lists
  them. Tidying any of them up breaks the one thing this project exists to do.
