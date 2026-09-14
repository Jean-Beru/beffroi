# Roadmap

The hardest part first. Each spike has a success criterion and a failure criterion written before it starts, and an end date. Failing in two weeks beats failing in three months.

| When | What | Output |
|---|---|---|
| 2026-09-14 to 2026-09-27 | Spike 1, conformance ([#21](https://github.com/Spomky-Labs/heidi/issues/21)) | Basic OP profile green, `oidc-demo` connected without a patch |
| 2026-10-01 | Go / no-go | If go: public repository under MIT, first tag |
| October 2026 | Spike 2, key custody ([#22](https://github.com/Spomky-Labs/heidi/issues/22)); the standalone application | One tenant, keys sealed by Vault Transit, rotation without outage; decision: hosted, or licence only |
| Early November 2026 | Spike 3, federation ([#23](https://github.com/Spomky-Labs/heidi/issues/23)) | Google Workspace and Entra by domain discovery, Keycloak import without reset |
| 2026-11-26 and 27 | SymfonyCon Warsaw | Demo: an OpenID conformant OP in PHP, a Symfony application logging in with a passkey |
| 2026-11-28 | Hackday | Repository open to contributors |

## Why this order

Two things are hard: a conformant OP, and keeping other people's signing keys. Without the first there is no product at all; the second only concerns a hosted version. Federation comes third because no company buys without it, but it only makes sense on an OP that holds.

## Not before December

Admin UI beyond the strict minimum, social login beyond Google and Entra, SCIM, SAML, CIBA, device flow, billing, website, product name. The identity model provides for all of it from the first commit.

## Versions

Development targets Symfony 8.2 (development branches until its release) on PHP 8.4 or later; CI runs on PHP 8.5. The first release meant for enterprise deployment aligns on the 8.4 LTS expected at the end of 2027.
