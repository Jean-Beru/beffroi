# Security defaults

The OP does not offer the option to do it wrong. The rules of RFC 9700, OAuth 2.1 and RFC 8725 are product decisions, not configuration:

- PKCE `S256` mandatory for every client; `plain` does not exist. A confidential client may be registered with `requires_pkce: false` (decision 0008 of the design repository, the named exception for the OpenID certification profiles, which send no `code_challenge`); a challenge it sends is verified all the same, a `code_verifier` without a challenge is refused (RFC 9700 §4.8.2), and a public client cannot hold the exception.
- No implicit grant, no resource owner password credentials.
- Redirect URIs match exactly.
- `iss` in every authorization response (RFC 9207), success or error.
- Access tokens are `at+jwt` (RFC 9068) or opaque and introspectable (RFC 7662, signed response RFC 9701), per client (`access_token_format`, `jwt` by default), with `aud` and `scope` in both shapes; revocation (RFC 7009) of what can be revoked, `unsupported_token_type` for a self-contained token.
- No outbound request ever follows a redirect.
- No boolean coming from a third party is ever cast: `filter_var()` or a strict comparison, never `(bool)`.
- Refresh tokens rotate on every use; reuse revokes the family; logout revokes the session's tokens.
- No HMAC algorithm for ID tokens.
- Errors before the client and redirect URI are validated are shown to the user, never redirected.
- Interaction pages send `X-Frame-Options: DENY`, `Content-Security-Policy: frame-ancestors 'none'`, `Referrer-Policy: no-referrer`; token, UserInfo, introspection and revocation responses send `Cache-Control: no-store`.
- Bearer tokens are read from the `Authorization` header or the form body, never from the query string.

When a rule is a choice rather than a requirement of the specification, it is documented with its reason. When it blocks a legitimate case, a named and bounded exception is added, never a global switch. There is no `insecure_*` option and no "compatibility mode".

Choices that are not specification requirements:

| Choice | Reason |
|---|---|
| Authorization code lifetime 60 s | RFC 6749 §4.1.2 allows up to 10 minutes; a code serves one immediate round trip |
| Access token 10 minutes, in both shapes | The self-contained shape has no immediate revocation at a third-party resource server; a short lifetime bounds the exposure, and the opaque shape keeps it because a revocation is a facility, not a reason to live longer |
| Access token shape per client, `jwt` by default | Neither shape is the less secure one; the choice belongs to the client and to nothing global; `jwt` is what spike 1 issued and what relying parties verify offline |
| A revoked opaque token is removed, not flagged | The record never changes; an unknown token is refused like a revoked one (RFC 6750 §3.1); the `TokenRevoked` event is the trace |
| Introspection describes a token to the client it was issued to only, and refuses a public client | `aud` is that client until RFC 8707; RFC 7662 §2.2 and §4 forbid telling a caller that a token exists; §2.1 requires client authentication |
| Rotation and reuse detection for every client | RFC 9700 §4.13 recommends it for public clients; a confidential client whose secret leaked is a public client |
| Consent required by default, `requiresConsent=false` per client | Consent is the rule; the first-party application is the named exception, carried by the client |
| PKCE required by default, `requiresPkce=false` per confidential client | PKCE is the rule; the client of a certification profile without PKCE is the named exception, carried by the client, with its scope and its removal condition in decision 0008 |
| Locale outside the URL | The RP does not know the user's language; an interaction URL must not vary with it |
| No synchronous write outside protocol needs | An authentication request never waits for an enrichment, a log or a purge |
| Two route planes | An attack on login must not stop `/token` and `/jwks` from answering |

Report a vulnerability privately: see `SECURITY.md` in the repository.
