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
- No HMAC algorithm for ID tokens, and no `none` (RFC 8725 §3.1): the provider signs with RS256, PS256, ES256 or EdDSA over Ed25519, one key per algorithm, and a client registers one of the names the discovery document announces or takes the default.
- Errors before the client and redirect URI are validated are shown to the user, never redirected.
- Interaction pages send `X-Frame-Options: DENY`, `Content-Security-Policy: frame-ancestors 'none'`, `Referrer-Policy: no-referrer`; token, UserInfo, introspection and revocation responses send `Cache-Control: no-store`.
- Access tokens are read from the `Authorization` header or, for a bearer token, from the form body, never from the query string.
- An access token issued to a client that authenticated with its certificate is bound to it (RFC 8705 §3): UserInfo serves it to a request presenting that certificate again and answers `invalid_token` to any other, in both shapes of token, so that a stolen bound token opens nothing. A certificate is compared and not the public key inside it, so a certificate reissued on the same key is another certificate.
- An access token bound to a key (RFC 9449 §6.1) is honoured only for a request carrying a proof signed with that key, made for that request and naming that very token in its `ath`; presented as a bearer token, or with a proof of another key, it is `invalid_token` and the challenge says `DPoP`. A proof is used once, its `jti` remembered for as long as it is accepted, and its `htu` is compared with the URL the provider publishes for the endpoint, never with what a proxy wrote in a header. A request proving both a certificate and a key is refused: a token is bound to one thing, and choosing which would be the provider deciding what the client meant.
- A request object is read before anything of it is trusted (RFC 9101 §6.1): the algorithm is the one the client registered in `request_object_signing_alg`, the key is one the client publishes, and `jwk`, `jku` and `x5c` are ignored (RFC 8725 §3.10). A signed object carries `iss`, `aud`, `nbf` and `exp`, the last two bounded, and the `client_id` inside it is the one the request names outside it. An unsigned object is the named exception: it is read from a client that registered `request_object_signing_alg: none`, which no FAPI client does, and only the `client_id` rule is asked of it, the rest of its claims proving nothing that its missing signature does not already say. A `request_uri` is read back only from a URL the client registered (`require_request_uri_registration` is true), and an unregistered one is refused without a request leaving the process.
- A client certificate is read from the variable the TLS listener fills from the handshake it carried out, never from a header; a request carrying one in `Ssl-Client-Cert`, `X-Ssl-Client-Cert`, `X-Client-Cert` or `X-Forwarded-Client-Cert` is refused rather than served without it, because nothing in front of the application sets one ([The client certificate at the edge](mtls-at-the-edge.md)).

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
| A code reserved for a key is refused to every other request | RFC 9449 §10 makes `dpop_jkt` optional; a code that names a key and is exchanged by another is a code the provider watched being stolen |
| A proof carrying an `ath` where the request presents no access token is refused | RFC 9449 §4.2 requires the claim only with a token; a proof naming one where none is presented was made for another request, and taking it would take a proof out of its context |
| A bound token refused rather than served as a bearer token | RFC 8705 §3 leaves the resource server to check the binding; the provider's own resource makes the check itself, because a token nobody checks the binding of is a bearer token with extra bytes |
| A certificate in a header is refused, not ignored | Ignoring it would let a deployment put behind a proxy that forwards one run for months before anyone noticed which of the two the provider believed; the configuration that makes a header trustworthy is part of what is delivered, and there is none |
| Five attempts a minute on a user's password, and five on a user's code, counted per user before anything is verified, never per address | A password and a six-digit code are guessed online one attempt at a time; an identity provider serves whole organisations behind one address, so a limiter keyed by the address (Symfony's `login_throttling`) refuses them as a whole. A correct password empties the count; an unknown username names no user and is counted nowhere, the decoy hash making it cost a wrong password all the same; a refused attempt is told "failed" like any other |

Report a vulnerability privately: see `SECURITY.md` in the repository.
