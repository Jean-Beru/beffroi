# Heidi

An identity provider for the Symfony ecosystem. OAuth 2.0 and OpenID Connect first, a pure-PHP identity core, a Symfony bundle, a standalone application. "Heidi" is the code name; the product name comes after the first spike.

| Page | What it covers |
|---|---|
| [Getting started](getting-started.md) | Clone, install, run the stack, run the quality tools |
| [Architecture](architecture.md) | Packages, layers, model, ports, endpoints, standing rules |
| [Security defaults](security-defaults.md) | What the OP refuses to do, and why |
| [The client certificate at the edge](mtls-at-the-edge.md) | How a client certificate reaches PHP, and why it is never read from a header |
| [Conformance suite](conformance-suite.md) | Running the OpenID Foundation suite locally against the OP |
| [Roadmap](roadmap.md) | The three spikes and their dates |

## Status

Spike 1 (2026-09-14 to 2026-09-27): a conformant OpenID Provider, proven by the Basic OP profile of the OpenID conformance suite, with a Symfony application logging in through the core `oidc_login` authenticator without a patch. Work is tracked in the [issues](https://github.com/Spomky-Labs/heidi/issues) and the [milestones](https://github.com/Spomky-Labs/heidi/milestones).

## Packages

| Package | Directory | Role |
|---|---|---|
| `heidi/core` | `src/core` | Tenants, users, credentials with typed hashes, linked identities, groups with a source, authentication sessions with provenance, signing keys. Pure PHP, knows no protocol. |
| `heidi/oidc` | `src/oidc` | OAuth 2.0 / OpenID Connect: clients, authorization requests, interactions, grants, tokens, discovery, JWKS, UserInfo, logout. Pure PHP. |
| `heidi/symfony-bundle` | `src/symfony` | Configuration, controllers, security, Doctrine mapping, login and consent pages, Messenger, translations. |
| `heidi/op` | `apps/op` | The standalone application on FrankenPHP, not published. |
