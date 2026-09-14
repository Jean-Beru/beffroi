# Contributing

Thank you for looking at Heidi. The project is in its first spike: the scope is narrow on purpose, and the decisions that shape it are settled. Read `CLAUDE.md` for the conventions and the wiki for the architecture.

## Before opening a pull request

- Open or pick an issue first; the milestones say what is in scope now.
- Run `castor prepare-pr` and `castor phpunit`. CI runs the same tools on PHP 8.5.
- Name tests after the specification section they verify.
- Do not add a security option. Security defaults are code; a legitimate blocked case gets a named, bounded exception, discussed in an issue first.
- Do not add a synchronous write unless the protocol needs its result in the same request; list any exception in `apps/op/config/packages/messenger.yaml` with its reason.
- Translate every user-facing string (`en`, `fr`).

## Commits

Conventional prefixes (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `ci:`), one topic per commit, English.

## Reporting a vulnerability

See `SECURITY.md`. Never in a public issue.
