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

Every QA task runs in `ghcr.io/spomky-labs/phpqa` when Docker is available. Castor exposes `snake_case` functions as `kebab-case` tasks. `castor.php` only imports `.castor/`, whose files share the global namespace so a task keeps the name of its function: `.castor/stack/` is what builds and checks the stack and what the CI runs (`stack.php`, `provision.php`, `qa.php`), `.castor/lab/` the tests and the experiments played against the running stack (`conformance.php`, `demo.php`, `mtls.php`). A new task goes to the file of its side.

```bash
composer install                  # monorepo (packages, tests)
(cd apps/op && composer install)  # the application, path repositories to ../../src/*
castor start                      # https://op.localhost (FrankenPHP), PostgreSQL, RabbitMQ; and https://mtls.op.localhost, the same application behind a listener that asks for a client certificate (docs/mtls-at-the-edge.md)
castor start --conformance        # plus the OpenID conformance suite on https://localhost:8443, profiler off; --access-token-format opaque for the suite clients
castor start --kms vault          # plus HashiCorp Vault (dev mode, docker/vault/init.sh at every start: Transit key of the tenant, policy of the OP); the OP runs in FrankenPHP worker mode either way
castor start --kms aws            # plus Floci 2.1.0 (AWS emulator, its KMS alone is used, docker/floci/init.sh at every start: the key of the tenant under alias/heidi-<slug>); it replaced LocalStack, whose community edition now needs an account
castor mtls [--host H] [--ordinary-host H]  # the client certificate from the edge to PHP (docs/mtls-at-the-edge.md): the certificate of "castor provision" presented to https://mtls.op.localhost, its x5t#S256 compared with the one the application computes, the same request without a certificate served all the same, the ordinary host asking for nothing and reading nothing, a certificate carried in a header refused
castor conformance [--plan P] [--module X]  # run the certification plans (basic, config, rp-initiated-logout, rotate-keys) through the API of the suite, scripted browser, key rotation done by the task; result per module
castor provision [--kms sodium|file|vault|aws]  # apps/op/.env.local (KMS DSN: a sodium key inline or in a file of the op container, a Vault token minted under the policy of the OP, or the alias on Floci; client secrets, password), tenant, signing key (a published one is opened with the KMS first, heidi:keys:list --check), user "alice" with a profile, and the self-signed client certificate of var/mtls/ that "castor mtls" presents
castor demo [--check] [--rotate] [--passkey] [--form-post] [--logout-others] [--resource-server]  # point ../oidc-demo (Symfony oidc_login) at the OP and start it on https://localhost:8002; --check signs in, opens /profile, logs out; --rotate runs a whole key rotation against it (about six minutes, short windows written into apps/op/.env.local for the run) and measures the refetch cooldown of oidc_login; --passkey signs in with a password, is sent back by /vault with acr_values=phr, enrols a passkey and signs the assertion with the software authenticator of tests/demo/passkey-browser.php (run under the autoloader of the monorepo, castor loads none of it), opens /vault with acr=phr, logs out, revokes the passkey; --form-post configures the demo with response_mode=form_post and posts the page of the OP back to its callback, with the session cookie and without it, which is what SameSite makes of a cross-site POST; --logout-others starts a second instance of the demo (php -S on http://demo.localhost:8003, client oidc-demo-second), signs it in on the same session and measures how long the back-channel logout takes to reach it once the first instance logs out; --resource-server signs in as the client oidc-demo-opaque, whose access token is opaque, and calls the three routes the demo serves behind an access_token firewall (/api/me by introspection, /api/me/signed by a signed introspection response whose keys come from /.well-known/oauth-authorization-server, /api/me/offline by verifying an at+jwt itself), revoking the token in between to show what each way makes of it; needs the demo on the Symfony branches of ../docs/specs/symfony-oauth-oidc-status.md (RP-14, RP-15 and RP-07) until they merge
castor tailwind [--watch]         # the stylesheet of the pages (Tailwind + DaisyUI) inside the op container
castor stop / castor logs / castor console <cmd>
castor console heidi:webauthn:mds-refresh [--url U] [--root R]  # the FIDO Metadata BLOB downloaded, verified under the pinned root (GlobalSign Root CA - R3 unless --root), stored in var/webauthn of the op container for the passkey ceremonies; by hand, never scheduled (a hosted-offer service); heidi:webauthn:mds-import <file> for a statement of a manufacturer or of the FIDO conformance tools
                                  # the FIDO Conformance Tools run by hand against https://op.localhost/fido/conformance (tests/conformance/README.md), the endpoints being imported by the application in dev only
castor phpunit            # tests with coverage
castor phpstan            # level max
castor ecs / castor ecs-fix
castor rector / castor rector-fix
castor deptrac
castor lint
castor check-licenses
castor prepare-pr         # ecs-fix, rector-fix, phpstan-baseline, deptrac, lint
castor infect --diff      # mutation testing of the lines changed since origin/main (--base to change), what CI runs on every PR and push; --reuse-coverage skips the PHPUnit run when .ci-tools/coverage is fresh
castor infect             # the whole source (core and oidc): hours, deliberate only; infection.json.dist sits at the root for the git diff, see .castor/stack/qa.php
```

Without a TTY (CI, agents), pass `</dev/null` or the Docker flag falls back to `-i` on its own.

## Conventions

- PHP 8.4, Symfony 8.2 (dev branches until release), `declare(strict_types=1)`, `final` by default, public readonly properties on value objects, no getters/setters on entities.
- No variadic parameter (`Type ...$values`): a function that takes several values takes a typed list (`@param list<Type> $values`). Spreading a list into a call (`...$arguments`) is not concerned.
- Test names cite the specification section they verify: `#[Test] public function itRejectsPlainPkceMethod(): void` with `RFC 7636 §4.3` in the docblock. The form of a test is fixed, see "Tests" below.
- Every secret string comes from `random_bytes()`, every secret comparison goes through `hash_equals()`, no boolean coming from a third party is ever cast.
- Security rules of decision 0006 are code, not configuration: no `insecure_*` option, no global compatibility switch.
- Functional tests boot `tests/symfony/Functional/AppKernel.php` with `APP_DEBUG=0`; bundles are listed in `tests/symfony/config/bundles.php`.
- Controllers are `final readonly`, one action per class, `#[Route]` on `__invoke()`. Route names carry their plane: `heidi_interaction_*` (browser: authorize, login, consent, logout) or `heidi_protocol_*` (server to server: discovery, jwks, token, userinfo, introspect, revoke). `HEIDI_PLANE` restricts a process to one plane. The endpoints of the FIDO conformance tools (`heidi_fido_conformance_*`, `src/symfony/src/Fido/Conformance/`) belong to no plane and to no environment but dev: their route file is imported by the application only, never by the bundle's `config/routes.php`, and the application never imports Symfony's `routing.controllers` resource, which would route every `#[Route]` service unprefixed.
- No write is synchronous unless the protocol needs its result in the same request; every exception is listed in `apps/op/config/packages/messenger.yaml` with its reason. Messages implement `Heidi\Bundle\Message\{Command,Query,Event,SyncMessage}`; handlers live in `MessageHandler/` and call the use cases of the core. The core dispatches PSR-14 events only.
- Every user-facing string is translated (XLIFF intl-icu, domain `heidi`, `en` and `fr`). The locale of an interaction comes from `ui_locales`, then `Accept-Language`, never from the URL.
- Every session and event carries a `RequestContext` (IP, user agent, later GeoIP and device); enrichment is always asynchronous.

## SOLID

A rule of every PR, not a theme of a review. The review of 2026-09-20 (issue #97, PRs #102 to #106) fixed the forms below; each one names the class to imitate.

- **One responsibility per class.** A block written a second time becomes a use case or a value object, never a third copy: opening a session is `SessionOpener` (the counterpart of `SessionTerminator`), revoking a set of refresh tokens is `RefreshTokenRevocation`, reading a scope list is `Scope::parseList()`, what a session had proven at a grant is `AuthenticationSnapshot`, a consent extends itself (`Consent::extendedWith()`). A use case orchestrates; a rule of an entity lives on the entity. A command that reads is not the command that writes (`heidi:user:show`, `heidi:user:profile`).
- **Open by addition.** A new credential kind, grant, hasher, token format or authentication method is a class that implements the interface of its capability (`CredentialEnrolmentInterface`, `GrantInterface`, `AlgorithmPasswordHasherInterface`, `AccessTokenIssuerInterface` per format), tagged or listed in the wiring; never a `match` on kinds, an enum of kinds, a registry by class (`EXTERNAL_ID_FIELDS` was the last one) or a class name read. A kind names itself (`Credential::kind()`) and declares what it can do by an interface (`RevocableCredentialInterface`, `ExternallyIdentifiedCredentialInterface`). A closed set the protocol fixes (an algorithm, a PKCE method, a response mode) may be an enum; a set the wiring decides may not.
- **One source of truth.** What the provider announces is derived from what is wired: the discovery document reads the tagged grants and `ClientAuthenticator::methods()`, never an enumeration kept in parallel. Two places that must agree are one place.
- **Substitutable.** What an implementation throws is in the contract of its interface (`@throws`, and a precondition such as `supports()` is on the contract that has it, not on the port a use case sees). A subtype narrows a return type, never widens a precondition. Intersection types (`Credential&RevocableCredentialInterface`) over downcasts.
- **Small interfaces, per capability.** A port has one to five methods, a caller sees what it calls and nothing else (`PasswordHasherInterface` for the use cases, `AlgorithmPasswordHasherInterface` for the registry; the `CanRevoke*` companions of the access token repository). When two callers use disjoint halves of a port, split it.
- **Depend inwards.** `Domain` depends on PHP, PSR, the core and the bricks of `docs/09-briques.md` (webauthn-lib in the core's model is the one named exception); `Application` on `Domain` and `Port`; `Bridge` implements. Deptrac (`.ci-tools/deptrac.yaml`) enforces it; a new dependency is a layer added there with its reason, never a rule relaxed.
- **What the current spike cannot absorb** goes to an issue tied to the spike that makes it necessary (decision 0005), with the pattern to reproduce named in it, as #98 to #101 were; it is not built ahead and not left unwritten.

## Tests

Same form as the maintainer's other projects. Every test, unit or functional, present or to come, follows it.

- One test verifies one behaviour. Several assertions are fine when they describe the single outcome (the fields of the object created, the claims of the token issued, the event recorded); a test never verifies an acceptance and a refusal, two calls with different inputs, or two rules of the specification. Split it, or use a data provider.
- Every test is laid out in three blocks introduced by `// Given`, `// When` and `// Then`, in that order, separated by a blank line. `// Given` is omitted when `setUp()` and the fixtures already provide everything; `// When / Then` joins the last two when the call is the assertion (a one-line `assertSame` on a constructor or a pure function).
- Expected exception: `// Given`, then `// Then` with `expectException()` and `expectExceptionMessageIs()` (or `expectExceptionMessageIsOrContains()` for a fragment; `expectExceptionMessage()` is deprecated in PHPUnit 13), then `// When` with the call as the last statement. When the test needs a property of the exception the message does not carry (`redirectable`, `reason`, `interactionId`, `getPrevious()`), catch it: `// When` on the `try`, `static::fail()` right after the call, `// Then` inside the `catch`. The state left after a failure is another test, whose `// When` swallows the exception with an empty `catch`. A class that repeats the same failing call may wrap it in a private helper whose name says so (`failToAuthenticate()`), returning the exception or nothing, called under `// When`.
- Same behaviour on several inputs: `#[DataProvider('provideXxx')]` and a `public static function provideXxx(): iterable` with named cases (`yield 'empty' => ['']`), declared right after the test that uses it.
- Doubles: the fixtures (`tests/*/Fixture`) and the in-memory adapters of the `Bridge` first; `createStub()` for a dependency without expectations, `createMock()` only to verify a call.
