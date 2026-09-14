# Security defaults

The OP does not offer the option to do it wrong. The rules of RFC 9700, OAuth 2.1 and RFC 8725 are product decisions, not configuration:

- PKCE `S256` mandatory for every client; `plain` does not exist.
- No implicit grant, no resource owner password credentials.
- Redirect URIs match exactly.
- `iss` in every authorization response (RFC 9207), success or error.
- Access tokens are `at+jwt` (RFC 9068) with `aud` and `scope`.
- No outbound request ever follows a redirect.
- No boolean coming from a third party is ever cast: `filter_var()` or a strict comparison, never `(bool)`.
- Refresh tokens rotate on every use; reuse revokes the family; logout revokes the session's tokens.
- No HMAC algorithm for ID tokens.
- Errors before the client and redirect URI are validated are shown to the user, never redirected.
- Interaction pages send `X-Frame-Options: DENY`, `Content-Security-Policy: frame-ancestors 'none'`, `Referrer-Policy: no-referrer`; token and UserInfo responses send `Cache-Control: no-store`.
- Bearer tokens are read from the `Authorization` header or the form body, never from the query string.

When a rule is a choice rather than a requirement of the specification, it is documented with its reason. When it blocks a legitimate case, a named and bounded exception is added, never a global switch. There is no `insecure_*` option and no "compatibility mode".

Choices that are not specification requirements:

| Choice | Reason |
|---|---|
| Authorization code lifetime 60 s | RFC 6749 §4.1.2 allows up to 10 minutes; a code serves one immediate round trip |
| Access token 10 minutes, stateless | No immediate revocation without storage or introspection; a short lifetime bounds the exposure |
| Rotation and reuse detection for every client | RFC 9700 §4.13 recommends it for public clients; a confidential client whose secret leaked is a public client |
| Consent required by default, `requiresConsent=false` per client | Consent is the rule; the first-party application is the named exception, carried by the client |
| Locale outside the URL | The RP does not know the user's language; an interaction URL must not vary with it |
| No synchronous write outside protocol needs | An authentication request never waits for an enrichment, a log or a purge |
| Two route planes | An attack on login must not stop `/token` and `/jwks` from answering |

Report a vulnerability privately: see `SECURITY.md` in the repository.
