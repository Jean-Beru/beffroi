# heidi/framework

An identity provider for the Symfony ecosystem. "Heidi" is the code name; the product name comes later.

| Package | Directory | What it is |
|---|---|---|
| `heidi/core` | `src/core` | Identity core: tenants, users, credentials, linked identities, groups, authentication sessions, signing keys. Pure PHP. |
| `heidi/oidc` | `src/oidc` | OAuth 2.0 / OpenID Connect module. Pure PHP. |
| `heidi/symfony-bundle` | `src/symfony` | Symfony integration. |
| `heidi/op` | `apps/op` | The standalone application (not published). |

Requires PHP 8.4 and Symfony 8.2.

See [docs/](docs/README.md) for the architecture, the security defaults and the conformance suite.

## Development

```bash
composer install
castor phpunit
castor prepare_pr
```

Every task runs inside the `ghcr.io/spomky-labs/phpqa` image when Docker is available.
