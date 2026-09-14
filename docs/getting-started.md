# Getting started

Requirements: PHP 8.4 or later (8.5 is what CI runs), Composer 2, Docker with Compose, [Castor](https://castor.jolicode.com/).

```bash
git clone git@github.com:Spomky-Labs/heidi.git
cd heidi
composer install                   # the monorepo: packages and tests
(cd apps/op && composer install)   # the application; heidi/* are path repositories to ../../src
castor start                       # https://op.localhost, PostgreSQL, RabbitMQ
```

Symfony 8.2 is not released yet: `minimum-stability: dev` pulls the `8.2.x-dev` branches, including `symfony/key-management`.

## The stack

| Service | Where | Notes |
|---|---|---|
| `op` | https://op.localhost | FrankenPHP, TLS from Caddy's internal CA. Every `*.localhost` name is loopback for browsers and modern resolvers. |
| `database` | internal | PostgreSQL 16, user and database `heidi` |
| `rabbitmq` | http://localhost:15672 | Management UI, `heidi` / `heidi` |
| conformance suite | https://localhost:8443 | `castor start --conformance`, see [Conformance suite](conformance-suite.md) |

To make your browser trust `https://op.localhost`, export Caddy's root certificate and install it on your machine:

```bash
docker compose cp op:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt
```

## Quality tools

Every tool runs inside `ghcr.io/spomky-labs/phpqa` through Castor. Task names are kebab-case.

```bash
castor phpunit
castor phpstan          # level max
castor ecs              # castor ecs-fix to apply
castor rector           # castor rector-fix to apply
castor deptrac          # package graph and layers
castor lint
castor check-licenses
castor prepare-pr       # ecs-fix, rector-fix, phpstan-baseline, deptrac, lint
```

CI runs the same tasks on PHP 8.5. Mutation testing (Infection) runs on `main` and release branches.

## Conventions in one screen

- `declare(strict_types=1)`, `final` by default, public readonly properties on value objects, no getters and setters on entities.
- Controllers are `final readonly`, one action per class, `#[Route]` on `__invoke()`.
- Test names cite the specification section they verify.
- Every secret comes from `random_bytes()`, every secret comparison goes through `hash_equals()`, no boolean coming from a third party is ever cast.
- No synchronous write unless the protocol requires it; the exceptions are listed in `apps/op/config/packages/messenger.yaml` with their reason.
- Every user-facing string is translated (`en`, `fr`).
