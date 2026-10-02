# beffroi/framework

An identity provider for the Symfony ecosystem.

| Package | Directory | What it is |
|---|---|---|
| `beffroi/core` | `src/core` | Identity core: tenants, users, credentials, linked identities, groups, authentication sessions, signing keys. Pure PHP. |
| `beffroi/oidc` | `src/oidc` | OAuth 2.0 / OpenID Connect module. Pure PHP. |
| `beffroi/symfony-bundle` | `src/symfony` | Symfony integration. |
| `beffroi/op` | `apps/op` | The standalone application (not published). |

Requires PHP 8.4 and Symfony 8.2.

## Development

```bash
composer install
castor phpunit
castor prepare_pr
```

Every task runs inside the `ghcr.io/spomky-labs/phpqa` image when Docker is available.
