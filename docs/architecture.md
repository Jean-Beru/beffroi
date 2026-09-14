# Architecture

The full design document lives with the project documentation; this page is the part a contributor needs.

## Packages and layers

```
src/core      heidi/core            identity core, pure PHP
src/oidc      heidi/oidc            OAuth 2.0 / OpenID Connect module, pure PHP, depends on the core
src/symfony   heidi/symfony-bundle  Symfony integration, depends on both
apps/op       heidi/op              the application, depends on the bundle
```

Inside each pure-PHP package, four layers checked by Deptrac:

| Layer | Contents | May depend on |
|---|---|---|
| `Domain` | Model objects, value objects, invariants, typed exceptions | PHP, PSR-20 |
| `Port` | Interfaces to the outside: repositories, signing, hashing, clock, events | `Domain` |
| `Application` | Use cases, one per endpoint or interaction step | `Domain`, `Port` |
| `Bridge` | Implementations of the ports on a third-party brick (jwt-framework, key-management) and in-memory adapters for tests | everything above |

The core never depends on a protocol; protocols never depend on each other; nothing below the bundle sees Symfony's HTTP, DI or Doctrine. SAML and SCIM, when they come, are modules next to `heidi/oidc`.

## The identity core

- `Tenant`: an issuer, its keys, its users, its clients. The issuer URL may carry a path.
- `User`: a stable `subject` distinct from the technical id, so that an import from another IdP keeps its `sub`. Standard profile claims. `emailVerified` is a boolean, never a string.
- `Credential`: N per user. `PasswordCredential` carries a typed `PasswordHash` (algorithm and parameters). Passkeys and TOTP are future subclasses.
- `LinkedIdentity`: an identity at an upstream provider. `Group` and `GroupMembership` carry a `source` (local, upstream claims, SCIM); the source wins over manual edits.
- `AuthenticationSession`: who is authenticated, since when (`auth_time`), how (`amr`, `acr`) and from where: two `RequestContext` (creation, last seen) with IP, user agent, and later GeoIP and device. Sessions end one by one.
- Signing keys: `SigningKeyProviderInterface` gives the active key and the publishable set of a tenant. The private key is sealed as a `symfony/key-management` envelope and exists in clear only in process memory; jwt-framework signs. The KMS keeps, it does not sign.
- Events: every event carries `occurredAt`, the tenant and the `RequestContext` of the request that produced it.

## The OIDC module

- `Client` with exact-match redirect URIs, hashed secret, `requiresConsent` per client.
- `AuthorizationRequest` validated in two stages: client and redirect URI first (errors are shown, never redirected), everything else after (errors are redirected with `error`, `state`, `iss`).
- `Interaction`: the authorization endpoint parks the request; the integration authenticates and asks for consent; `AuthorizationHandler::begin()` returns `LoginRequired`, `ConsentRequired` or `Granted(code)`.
- Grants: `authorization_code` with PKCE S256 and replay detection, `refresh_token` with rotation and reuse detection.
- Tokens: `at+jwt` access tokens, ID tokens with `at_hash` and `sid`, opaque refresh tokens stored hashed.
- Discovery, JWKS with several keys, UserInfo, RP-Initiated Logout revoking the session's refresh tokens.

## The bundle

- Routes belong to one of two planes, and the route name says which: `heidi_interaction_*` (browser: authorize, login, consent, logout) and `heidi_protocol_*` (server to server: discovery, jwks, token, userinfo). `HEIDI_PLANE` makes a process refuse the routes of the other plane, so that an attack on login cannot take the token endpoint down.
- Messenger with RabbitMQ: three buses (`command.bus` transactional, `query.bus`, `event.bus`), three AMQP transports by priority, `failed` on Doctrine, everything synchronous in tests. The core's PSR-14 events are replayed on `event.bus`.
- Doctrine XML mapping of the pure classes, tables prefixed `heidi_`, `tenant_id` everywhere.
- Own user provider and form login on the bundle's identity store; never the host application's `User`.
- Translations `en` and `fr`; the locale of an interaction comes from `ui_locales`, then `Accept-Language`, never from the URL.
