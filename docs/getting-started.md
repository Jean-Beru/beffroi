# Getting started

Requirements: PHP 8.4 or later (8.5 is what CI runs), Composer 2, Docker with Compose, [Castor](https://castor.jolicode.com/).

```bash
git clone git@github.com:Spomky-Labs/heidi.git
cd heidi
composer install                   # the monorepo: packages and tests
(cd apps/op && composer install)   # the application; heidi/* are path repositories to ../../src
castor start                       # https://op.localhost, PostgreSQL, RabbitMQ
castor provision                   # the tenant, a signing key, the user "alice" with a profile; see below
castor demo --check                # oidc-demo (Symfony oidc_login) against the OP; see below
```

Symfony 8.2 is not released yet: `minimum-stability: dev` pulls the `8.2.x-dev` branches, including `symfony/key-management`.

## Provisioning the development OP

A fresh stack has a schema (the container runs the migrations at start-up) and nothing else. `castor provision` does the rest, in the order of the console commands of the bundle, and can be run again at any time:

1. It writes the development values `apps/op/.env.local` lacks and keeps every one it finds: a sodium key for the KMS that seals the signing keys (`HEIDI_KMS_DSN`, `HEIDI_KMS_KEY_ID`), one secret per client of `apps/op/config/packages/heidi.yaml` (the three clients of the conformance suite, `oidc-demo`), the password of the development user (`HEIDI_DEV_USER_PASSWORD`). Nothing secret is committed: `apps/op/.env` leaves them empty on purpose, and a process without a KMS DSN seals nothing.
2. `heidi:tenant:synchronize`, `heidi:keys:generate` unless a key is published already (a second generation would be a rotation without a staging window; `heidi:keys:rotate` is the one without an outage, see [architecture](architecture.md)), `heidi:user:create alice` unless the user exists, `heidi:user:profile alice` with every claim of OIDC Core §5.1 the `profile`, `phone` and `address` scopes stand for (the scope modules of the conformance plan check that UserInfo answers each scope), then `heidi:user:set-password alice` from the standard input.
3. It prints where to look: the discovery document, the JWK Set, the username and the password, and the secret of each client, which `oidc-demo` and `castor conformance` take from `.env.local`.

The pages of the interaction plane (login, consent, logout) are styled by the application: `apps/op/templates/bundles/HeidiBundle/layout.html.twig` overrides the layout of the bundle, and `apps/op/assets/styles/app.css` builds Tailwind with the DaisyUI plugin through `symfonycasts/tailwind-bundle` (the binary is pinned in `config/packages/symfonycasts_tailwind.yaml`, DaisyUI in `importmap.php`). The container builds the stylesheet at start-up; `castor tailwind --watch` rebuilds it while you edit.

## oidc-demo, the reference client

`oidc-demo` is the Symfony application on the `oidc_login` authenticator of Symfony 8.2, the client the OP is written against: whatever the OP emits must be consumable by it without a patch. It lives in its own repository, checked out next to this one (`../oidc-demo`, or `../../oidc-demo` when this repository is nested in the design one; `--dir` otherwise), on the `8.2` branch of Symfony for `symfony/security-http`, `security-core` and `security-bundle`, since the authenticator, `iss` on the callback, the refresh of the access token and the RP-Initiated Logout were merged there after the original pull request.

`castor demo` writes the issuer, the client `oidc-demo` and its secret (from `apps/op/.env.local`) into the `.env.local` of the demo, never into its `.env`; exports the root certificate of Caddy into `var/caddy-root.crt` of the demo and writes a `php.ini` next to it (`openssl.cafile`, `curl.cainfo`), which the Symfony CLI reads, so that the PHP of the host trusts `https://op.localhost` without touching the machine; clears the cache of the demo, where the discovery document of the previous issuer may live; then starts `symfony server:start --port=8002 --daemon`. `castor demo --stop` stops it.

`castor demo --check` then does what a browser does, one request at a time, no redirect followed: `/profile` of the demo, the authorization request (`response_type=code`, PKCE `S256`, `nonce`, `state`), the login form of the OP as `alice`, the callback with `code`, `state` and `iss` (RFC 9207), `/profile` open with the claims of UserInfo, an ID token and an `at+jwt` access token, then `/logout`, the round trip through the end session endpoint with `id_token_hint`, and a new authorization request that lands on the login page again because the session of the OP ended. The refresh of the access token (`refresh_access_token`) is not in the check: it happens on the first request after the token expired, ten minutes after the login; sign in from a browser, open `/profile` again then and compare the `jti`.

The firewall of the demo: `client_authentication: { client_secret_post: ... }` (the method the OP registered the client with), `scope: [openid, profile, email]`, `refresh_access_token: true`, `enable_end_session: true`, `post_logout_redirect_path: /`, everything else at its default.

## The stack

| Service | Where | Notes |
|---|---|---|
| `op` | https://op.localhost | FrankenPHP, TLS from Caddy's internal CA. Every `*.localhost` name is loopback for browsers and modern resolvers. The web debug toolbar is on every page and the profiler at `/_profiler` (`symfony/web-profiler-bundle` and `symfony/debug-bundle` in `require-dev`, `dev` only; the production stage of the Dockerfile installs with `--no-dev`, so neither ships). Requests to `/.well-known/` are not collected, and nothing is while the stack serves the conformance suite (`castor start --conformance` sets `APP_PROFILER=0`). |
| `worker` | internal | The same image, `messenger:consume` of the three transports of the buses and of `scheduler_heidi`, the schedule of the bundle that finishes a rotation on time. The sealed keys are files: `op` and `worker` share the `keys_data` volume, or a rotation in one would change nothing in the other. |
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
castor infect --diff    # mutation testing of the lines changed since origin/main; escaped mutants are listed in .ci-tools/infection.txt
```

CI runs the same tasks on PHP 8.5. Mutation testing (Infection) runs on every pull request and every push to `main` and release branches, on the lines the change adds or modifies; `castor infect` without `--diff` mutates the whole source and takes hours.

## Conventions in one screen

- `declare(strict_types=1)`, `final` by default, public readonly properties on value objects, no getters and setters on entities.
- Controllers are `final readonly`, one action per class, `#[Route]` on `__invoke()`.
- Test names cite the specification section they verify.
- Every secret comes from `random_bytes()`, every secret comparison goes through `hash_equals()`, no boolean coming from a third party is ever cast.
- No synchronous write unless the protocol requires it; the exceptions are listed in `apps/op/config/packages/messenger.yaml` with their reason.
- Every user-facing string is translated (`en`, `fr`).
