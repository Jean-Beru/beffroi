# The client certificate at the edge

Everything mutual TLS asks of an OpenID Provider (client authentication of RFC 8705, an access token bound to the certificate of its client) begins with one question of infrastructure: can a certificate presented at the TLS handshake reach PHP, and is what arrives the bytes the client presented rather than something a client could have written itself? This page is the answer, measured on the development stack, and the configuration that makes it true. What the provider then does with the certificate is the last section.

Measured with `dunglas/frankenphp:1-php8.5` as `apps/op/Dockerfile` pins it: FrankenPHP 1.12.7, Caddy 2.11.4, PHP 8.5.10, in worker mode, which is how the application runs in development and in production. `castor mtls` replays every line of it against the running stack.

## What is served

Two hosts, one TLS listener:

| Host | Asks for a client certificate | Serves |
|---|---|---|
| `op.localhost` (`SERVER_NAME`) | no, never | everything: the browser, the conformance suite, `oidc-demo` |
| `mtls.op.localhost` (`MTLS_SERVER_NAME`) | yes, without requiring one | the same application, and it is the host a client will be pointed at by `mtls_endpoint_aliases` |

The second host lives in `apps/op/frankenphp/mtls.Caddyfile`, a site block of its own imported by `CADDY_EXTRA_CONFIG` (`import mtls.Caddyfile`), the way the worker mode is imported by `FRANKENPHP_CONFIG`. `compose.yaml` sets both variables and gives the `op` service the network alias `mtls.op.localhost`, so a container of the stack reaches it the way a browser on the machine does. A deployment that serves no mTLS endpoint leaves `CADDY_EXTRA_CONFIG` empty and has one host, as before.

`mode request` is what "asks without requiring" means in Caddy: the client is asked for a certificate, and a client that presents none is served all the same. A provider needs exactly that, because a client that authenticates with a secret or with a private key must not fail at the handshake, and because `self_signed_tls_client_auth` (RFC 8705 §2.2) presents a certificate that chains nowhere. The handshake still proves the client holds the private key of what it presented: a certificate is only accepted with its `CertificateVerify` signature (RFC 8446 §4.4.3). What it does not prove is a chain, which matters below.

## What reaches PHP

The site block hands the certificate over in one server variable:

```
php_server {
	env SSL_CLIENT_CERT {http.request.tls.client.certificate_pem}
}
```

Measured:

- The placeholder is replaced **per request**, in worker mode as well: the same worker serves a request with a certificate and the next one without, and reads the right thing both times.
- The value is a **PEM envelope with real line breaks**, holding the **leaf and nothing else**. There is no chain: `{http.request.tls.client.certificate_pem_chain}` is not a placeholder of Caddy 2.11 and comes through as its own literal text.
- On a request made **without** a certificate the variable is **not empty**: it is an envelope with nothing in it, `-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n`. Anything that treats "the variable is set" as "a certificate was presented" is wrong. `Heidi\Oidc\Domain\Client\Certificate\ClientCertificate` reads an empty envelope as "no certificate".
- The same trap in a sharper form: `{http.request.tls.client.fingerprint}`, which is the SHA-256 of the DER in hexadecimal and therefore `x5t#S256` in another encoding, answers `e3b0c442…` for a request without a certificate, which is the SHA-256 of the empty string. A provider that bound a token to that would bind every unauthenticated client to the same value. This is why the thumbprint is computed here, from the DER, rather than taken from the edge.
- On the ordinary host the variable is **absent**, not empty: a variable exists only where the site block that serves the request puts it.

`{http.request.tls.client.certificate_der_base64}`, `{http.request.tls.client.subject}`, `{http.request.tls.client.issuer}` and `{http.request.tls.client.serial}` all answer as well, and none of them is passed: the leaf carries everything they say, one variable is one thing to keep in agreement, and what is read out of a certificate is a rule of client authentication, not of the edge.

## Why a variable and not a header

A client controls every header of its request and no variable of the process that serves it. A client sending `Ssl-Client-Cert: <a certificate of its choosing>` reaches PHP as `HTTP_SSL_CLIENT_CERT`, never as `SSL_CLIENT_CERT`, because that is what a CGI-style server does with a header. So the variable cannot be forged, and the header is never read.

The application does not stop at not reading it. `Heidi\Bundle\Http\Tls\EdgeClientCertificateResolver` **refuses** a request that carries a client certificate in `Ssl-Client-Cert`, `X-Ssl-Client-Cert`, `X-Client-Cert` or `X-Forwarded-Client-Cert`, whichever host it came to, and refuses it even when a real certificate was presented at the handshake beside it. Nothing in front of this application sets one of those headers, so their presence is somebody trying, and a deployment that is put behind a proxy which forwards one says so on its first request instead of trusting it silently (decision 0006: the configuration that makes the certificate trustworthy is delivered, not left to the operator's good sense).

## What a deployment has to do

- **Validating a chain happens at the edge.** Only the leaf reaches PHP, so `tls_client_auth` (RFC 8705 §2.1), which names a certificate authority the client must chain to, is configured with a `trust_pool` in the `client_auth` block of `mtls.Caddyfile`. The provider reads the leaf to see which client it names and nothing more: it never builds a chain, never looks at a validity period and never asks a revocation list anything, because a provider judging a chain from the leaf alone would be judging nothing. A deployment that turns `tls_client_auth` on is the deployment that configures the authorities its listener accepts. `self_signed_tls_client_auth` (§2.2) needs nothing there: what it authenticates is the leaf itself, compared with what the client published.
- **Say where the endpoints are reached.** `heidi.mutual_tls.origin` (`HEIDI_MTLS_ORIGIN` in the application) is the scheme and authority of the host whose listener asks for a certificate, and the discovery document announces the endpoints under it in `mtls_endpoint_aliases` (RFC 8705 §5). A deployment that serves one host leaves it empty and announces no alias.
- **Behind another proxy**, the certificate arrives some other way, almost always a header. That deployment supplies another `ClientCertificateResolverInterface` and a proxy configuration that overwrites the header on every request, so that what a client sent under that name is thrown away before the application sees it. Teaching the delivered resolver a header to trust is not an option, and there is no switch for it.
- **The ordinary host must keep asking for nothing.** It does, and `castor mtls` checks it: a client that offers a certificate to `op.localhost` is served and its certificate is read by nobody.

## What the second listener costs

Caddy turns on **strict SNI-Host enforcement for the whole listener** as soon as any site on it configures client authentication, and says so in its log at start-up. A request whose `Host` header does not match the name it asked for at the handshake is answered **421 Misdirected Request** instead of being served. Every ordinary client sends the two equal, and the six certification plans, the browser and `oidc-demo` are unaffected; a script that sets `Host` by hand against an address is not.

Nothing else changes for the ordinary host: the discovery document, the JWK Set and the interaction pages answer over HTTP/1.1 and HTTP/2 as before.

## What the provider does with it

The certificate is read by whoever authenticates a client (RFC 8705 §2) and by whoever honours a token (§3); the edge hands it over and judges nothing else.

- **`tls_client_auth` (§2.1)**: the client registers exactly one of the five values of §2.1.2 (`tls_client_auth_subject_dn`, `tls_client_auth_san_dns`, `tls_client_auth_san_uri`, `tls_client_auth_san_ip`, `tls_client_auth_san_email`), and the provider compares it with what the certificate says. The certificate is read with pki-framework, never with a regular expression over a distinguished name; a registered name is written back at boot by the same reader that writes the one it reads out of a certificate, so a name copied from `openssl x509 -noout -subject -nameopt RFC2253` is registered as it is printed.
- **`self_signed_tls_client_auth` (§2.2)**: the client publishes its certificate in its JWK Set, in the `x5c` of a key (RFC 7517 §4.7) or by the thumbprint of §4.9, and presenting that very certificate authenticates it. The certificate is compared, not the key inside it: the same names signed again are another certificate, and one the client has not published.
- **A certificate beside another credential**: a client reaching this host presents a certificate because the listener asked for one, not because it chose to authenticate with it. So a certificate presented beside a secret or an assertion is not a second authentication method of RFC 6749 §2.3: the credential of the request authenticates, and the certificate authenticates only the clients registered for one of the two methods above. RFC 8705 §3 lets a provider bind the tokens of a client authenticated otherwise to the certificate it presented; that is a registration of its own, which no client has here, and binding a client that never asked for it would break the resource server it calls.
- **Certificate-bound access tokens (§3)**: a token issued on a request authenticated that way carries the SHA-256 thumbprint of the certificate, in the `cnf` of the `at+jwt` (§3.1) and in the introspection response of an opaque one (§3.2). UserInfo, the protected resource of the provider, serves such a token to a request that presents that certificate again and answers `invalid_token` to any other, whichever shape the token has. A token issued to a client that proved no certificate is a bearer token and says so by carrying no `cnf` at all.
- **What the document announces**: `tls_client_auth` and `self_signed_tls_client_auth` in `token_endpoint_auth_methods_supported`, `tls_client_certificate_bound_access_tokens` (§3.3) and `mtls_endpoint_aliases` (§5), all three derived from what is wired and from the origin above, never from a list kept beside them.

## Driving it

```bash
castor start                      # both hosts
castor provision                  # issues var/mtls/client.crt and its key, and prints the thumbprint
castor mtls                       # the whole measurement, one line per thing to get right
```

`castor provision` issues one **self-signed** client certificate on a P-256 key, which is what the listener of the development stack asks for and accepts, and what `self_signed_tls_client_auth` uses. It is kept as long as it is valid, so a client registered under its thumbprint survives a second run. A certificate authority for clients is configuration of a deployment, not of this task.

The endpoint `castor mtls` drives, `/mtls/client-certificate`, is imported by the application **in development only** (`apps/op/config/routes/mtls.yaml`), as the endpoints of the FIDO conformance tools are. It answers `present` with the `x5t#S256` of RFC 8705 §3.1, `absent` when the request went through the listener without a certificate, or `refused` with a 400 when the request carried one in a header. It is a measurement of the edge, not an API of the product.
