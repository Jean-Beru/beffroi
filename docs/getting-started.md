# Getting started

Requirements: PHP 8.4 or later (8.5 is what CI runs), Composer 2, Docker with Compose, [Castor](https://castor.jolicode.com/).

```bash
git clone git@github.com:Spomky-Labs/heidi.git
cd heidi
composer install                   # the monorepo: packages and tests
(cd apps/op && composer install)   # the application; heidi/* are path repositories to ../../src
castor start                       # https://op.localhost, PostgreSQL, RabbitMQ
castor provision                   # the tenant, a signing key, the user "alice"; see below
```

Symfony 8.2 is not released yet: `minimum-stability: dev` pulls the `8.2.x-dev` branches, including `symfony/key-management`.

## Provisioning the development OP

A fresh stack has a schema (the container runs the migrations at start-up) and nothing else. `castor provision` does the rest, in the order of the console commands of the bundle, and can be run again at any time:

1. It writes the development values `apps/op/.env.local` lacks and keeps every one it finds: a sodium key for the KMS that seals the signing keys (`HEIDI_KMS_DSN`, `HEIDI_KMS_KEY_ID`), one secret per client of `apps/op/config/packages/heidi.yaml` (the three clients of the conformance suite, `oidc-demo`), the password of the development user (`HEIDI_DEV_USER_PASSWORD`). Nothing secret is committed: `apps/op/.env` leaves them empty on purpose, and a process without a KMS DSN seals nothing.
2. `heidi:tenant:synchronize`, `heidi:keys:generate` unless a key is published already (a second generation would be a rotation), `heidi:user:create alice` unless the user exists, then `heidi:user:set-password alice` from the standard input.
3. It prints where to look: the discovery document, the JWK Set, the username and the password, and the secret of each client, which `oidc-demo` and `castor conformance` take from `.env.local`.

The pages of the interaction plane (login, consent, logout) are styled by the application: `apps/op/templates/bundles/HeidiBundle/layout.html.twig` overrides the layout of the bundle, and `apps/op/assets/styles/app.css` builds Tailwind with the DaisyUI plugin through `symfonycasts/tailwind-bundle` (the binary is pinned in `config/packages/symfonycasts_tailwind.yaml`, DaisyUI in `importmap.php`). The container builds the stylesheet at start-up; `castor tailwind --watch` rebuilds it while you edit.

## The stack

| Service | Where | Notes |
|---|---|---|
| `op` | https://op.localhost | FrankenPHP, TLS from Caddy's internal CA. Every `*.localhost` name is loopback for browsers and modern resolvers. |
| `database` | internal | PostgreSQL 16, user and database `heidi` |
| `rabbitmq` | http://localhost:15672 | Management UI, `heidi` / `heidi` |
| conformance suite | https://localhost:8443 | `castor start --conformance`, then `castor conformance` runs the plan; see [Conformance suite](conformance-suite.md) |

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
