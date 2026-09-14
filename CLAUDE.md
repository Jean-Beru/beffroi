# CLAUDE.md

Monorepo of an identity provider for the Symfony ecosystem (code name "Heidi"; the product name comes later). The design lives in the parent repository: `../docs/11-architecture.md` and `../docs/decisions/`. Those decisions are settled; do not reopen them here.

## Packages

| Directory | Package | Namespace | Rule |
|---|---|---|---|
| `src/core` | `heidi/core` | `Heidi\Core` | Identity core. Pure PHP. Knows no protocol, no HTTP, no container, no Doctrine. |
| `src/oidc` | `heidi/oidc` | `Heidi\Oidc` | OAuth 2.0 / OpenID Connect. Pure PHP. Depends on the core only. |
| `src/symfony` | `heidi/symfony-bundle` | `Heidi\Bundle` | Symfony integration. The only place where `Request`, DI and Doctrine appear. |
| `apps/op` | `heidi/op` | `App` | Standalone application, FrankenPHP. |

Inside each pure-PHP package: `Domain`, `Port`, `Application`, `Bridge`. Deptrac enforces both the package graph and the layers (`.ci-tools/deptrac.yaml`).

## Commands

Every QA task runs in `ghcr.io/spomky-labs/phpqa` when Docker is available. Castor exposes `snake_case` functions as `kebab-case` tasks.

```bash
composer install                  # monorepo (packages, tests)
(cd apps/op && composer install)  # the application, path repositories to ../../src/*
castor start                      # https://op.localhost (FrankenPHP), PostgreSQL, RabbitMQ
castor start --conformance        # plus the OpenID conformance suite on https://localhost:8443
castor stop / castor logs / castor console <cmd>
castor phpunit            # tests with coverage
castor phpstan            # level max
castor ecs / castor ecs-fix
castor rector / castor rector-fix
castor deptrac
castor lint
castor check-licenses
castor prepare-pr         # ecs-fix, rector-fix, phpstan-baseline, deptrac, lint
```

Without a TTY (CI, agents), pass `</dev/null` or the Docker flag falls back to `-i` on its own.

## Conventions

- PHP 8.4, Symfony 8.2 (dev branches until release), `declare(strict_types=1)`, `final` by default, public readonly properties on value objects, no getters/setters on entities.
- Test names cite the specification section they verify: `#[Test] public function itRejectsPlainPkceMethod(): void` with `RFC 7636 §4.3` in the docblock.
- Every secret string comes from `random_bytes()`, every secret comparison goes through `hash_equals()`, no boolean coming from a third party is ever cast.
- Security rules of decision 0006 are code, not configuration: no `insecure_*` option, no global compatibility switch.
- Functional tests boot `tests/symfony/Functional/AppKernel.php` with `APP_DEBUG=0`; bundles are listed in `tests/symfony/config/bundles.php`.
- Controllers are `final readonly`, one action per class, `#[Route]` on `__invoke()`. Route names carry their plane: `heidi_interaction_*` (browser: authorize, login, consent, logout) or `heidi_protocol_*` (server to server: discovery, jwks, token, userinfo). `HEIDI_PLANE` restricts a process to one plane.
- No write is synchronous unless the protocol needs its result in the same request; every exception is listed in `apps/op/config/packages/messenger.yaml` with its reason. Messages implement `Heidi\Bundle\Message\{Command,Query,Event,SyncMessage}`; handlers live in `MessageHandler/` and call the use cases of the core. The core dispatches PSR-14 events only.
- Every user-facing string is translated (XLIFF intl-icu, domain `heidi`, `en` and `fr`). The locale of an interaction comes from `ui_locales`, then `Accept-Language`, never from the URL.
- Every session and event carries a `RequestContext` (IP, user agent, later GeoIP and device); enrichment is always asynchronous.
