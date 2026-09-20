# Conformance suite

The OpenID Foundation conformance suite is the external judge of spike 1, and of every certification profile the OP answers since. It runs locally from the prebuilt images of `registry.gitlab.com/openid/conformance-suite`, pinned by version in `compose.yaml`.

```bash
castor start --conformance
castor logs conformance-server
```

Then open https://localhost:8443 (self-signed certificate of the suite's nginx). `castor start --conformance` recreates the `op` container with `APP_PROFILER=0`: a plan of a hundred requests has no use for a hundred profiles, and the toolbar has no place in the pages the scripted browser reads. `castor start` alone puts the profiler back.

The three clients of the suite receive access tokens in the shape `CONFORMANCE_ACCESS_TOKEN_FORMAT` names (`jwt` by default): `castor start --conformance --access-token-format opaque` recreates the `op` container with opaque ones, and the plans must be green with either, since the suite presents the access token to UserInfo without looking at it. Both switches are environment variables of the container, documented in `apps/op/.env`.

## How the suite reaches the OP

- The `op` service has the network alias `op.localhost`, so the suite container resolves it like your browser does.
- Caddy issues the OP certificate from its internal CA. The suite container starts with `tests/conformance/server-entrypoint.sh`, which imports that CA into the JVM truststore before launching the suite exactly as the upstream image does. Everything else in the entrypoint is the upstream command line.
- Verified: a Java `HttpsURLConnection` from the suite container to `https://op.localhost` completes the TLS handshake.

## Gotchas met while wiring it

- The MongoDB property of the jar is `spring.data.mongodb.uri`.
- `SPRING_PROFILES_ACTIVE=dev` avoids the suite login, but the Google and GitLab OAuth registrations must be non-empty placeholders or Spring refuses to start. This mirrors the official `docker-compose-prebuilt.yml`.
- The nginx image proxies to `http://server:8080`: the server service needs the network alias `server`.
- The scripted browser of the suite runs inside the server JVM and follows the OP's redirect to `https://localhost:8443/...`, which is the container itself: the `conformance-redirector` sidecar (socat, same network namespace) forwards that loopback port to nginx, and the entrypoint imports the self-signed certificate of nginx into the JVM truststore next to the Caddy CA.
- An empty `POST` to `/api/runner` must not be sent as a form: Spring answers 415 to `application/x-www-form-urlencoded`, which Symfony's HttpClient adds by default.

## The certification plans

Four plans and one module on its own, one configuration, one task. `castor conformance` runs them all; `--plan basic`, `--plan config`, `--plan form-post`, `--plan rp-initiated-logout` or `--plan rotate-keys` (repeatable) runs one.

`--reset` empties the database of the OP before the plans run and provisions it again, then restarts the containers and waits for the discovery document: the plans were written against the OP `castor provision` leaves, a development user with a password and nothing else. A second factor or a passkey enrolled by hand, which a run of `castor demo --passkey` or an afternoon on the account pages leaves behind, stops the scripted browser of the suite on the page that asks for it, and every module of every plan then fails on the same line, `unexpected url for task: Verify complete`. The restart is not decoration: a worker of FrankenPHP holds the kernel and the opened signing key for every request it serves (architecture §3.3), and a worker that was up before the tables went keeps a key no row names any more. Nothing of the configuration is lost, the client secrets living in `apps/op/.env.local` and the clients in `apps/op/config/packages/heidi.yaml`.

The alias of the configuration is exclusive: two `castor conformance` at once on the same suite interrupt each other's modules with `Stopping test due to alias conflict`, and a `--reset` under a run in progress takes the tables from under it. One run at a time.

### Basic OP

`oidcc-basic-certification-test-plan`, created with `server_metadata=discovery` and `client_registration=static_client`. Its modules carry their own variant: all `client_secret_basic` except `oidcc-server-client-secret-post`, all `response_type=code` and `response_mode=default`. The plan needs three registered clients: `client` and `client2` in `client_secret_basic` (the second is the wrong client of some modules) and a `client_secret_post` one, because a client authenticates with the one method it registered.

The clients are registered in `apps/op/config/packages/heidi.yaml` (development only): `conformance-basic`, `conformance-basic-second` and `conformance-post`, all three with `requires_pkce: false`, the named exception of decision 0008 of the design repository: the Basic OP profile sends no `code_challenge` (one module out of thirty-five does, and it passes with the exception in place, since a challenge the client sends is verified all the same). Their secrets are generated by `castor provision` into `apps/op/.env.local` (`CONFORMANCE_BASIC_SECRET`, `CONFORMANCE_BASIC_SECOND_SECRET`, `CONFORMANCE_POST_SECRET`). The plan must use the alias `heidi`: the registered redirect URI is `https://localhost:8443/test/a/heidi/callback` and the post-logout one `https://localhost:8443/test/a/heidi/post_logout_redirect`. The user to sign in with is `alice`, password `HEIDI_DEV_USER_PASSWORD` of the same file; `castor provision` gives her every claim of OIDC Core §5.1 (`heidi:user:profile`), because the `oidcc-scope-*` and `oidcc-claims-essential` modules check that UserInfo answers each scope with its claims and end in a warning for a user without them.

### Config OP

`oidcc-config-certification-test-plan`, no variant, one module: `oidcc-discovery-endpoint-verification` reads the discovery document and checks it against OIDC Discovery §3. No browser, no client. It passed the day it was first run, on the document the Basic OP plan already read.

### Form Post OP

`oidcc-formpost-basic-certification-test-plan`, created with `server_metadata=discovery` and `client_registration=static_client`, the Basic OP plan run again with `response_mode=form_post`: the same modules, the same three clients, the same user, and an answer the OP gives as a page whose form the browser posts to the redirect URI instead of a redirection (OAuth 2.0 Form Post Response Mode §2). Nothing else moves: the profile is Basic, so its modules ask for `response_type=code` and no other, and an error of the authorization endpoint comes back posted like a success (OIDC Core §3.1.2.6).

The scripted browser needs nothing added: the page it receives submits itself, HtmlUnit running its one script, and the `Verify complete` task of the `browser` section waits for the callback of the suite as it does after a redirection. The page carries a `Content-Security-Policy` of `default-src 'none'` naming that script by hash; HtmlUnit does not enforce CSP, so the policy is judged by the functional tests of the bundle, not by the suite.

The suite creates 35 of the 38 modules the plan lists for these variants. One of them, `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported`, the OP cannot answer yet and is listed as known in `CONFORMANCE_PLANS`: the module writes `response_mode=form_post` only inside the request object it sends, never in the query, and the OP refuses the object unread (`request_not_supported`, OIDC Core §6, which the module accepts as a rejection) so the refusal goes back in the default mode and the form post checks of the callback fail. The same module ends `SKIPPED` in the Basic OP plan, where `response_mode=default` makes those checks absent. It closes with JAR (RFC 9101), which spike 5 brings: issue heidi#142. A module listed as known is reported as `KNOWN` and accepted, and the run fails the day it passes, so that the line is deleted rather than carried.

### RP-Initiated Logout OP

`oidcc-rp-initiated-logout-certification-test-plan`, created with `response_type=code` and `client_registration=static_client`; its eleven modules run with `client_secret_basic` on `client`. One checks the discovery document (`end_session_endpoint`), ten sign in through the authorization flow then call the end session endpoint: the nominal request (verified `id_token_hint`, registered `post_logout_redirect_uri`, `state`) and the same without `state` must land on `https://localhost:8443/test/a/heidi/post_logout_redirect`; a request with nowhere to go (`no-params`, `only-state`, `no-post-logout-redirect-uri`) must end the session and show it; a request that cannot be honoured (`post_logout_redirect_uri` not registered or with a query added, `id_token_hint` modified or issued to no client, `post_logout_redirect_uri` without `id_token_hint` or `client_id`) must show an error page and redirect nowhere (RP-Initiated Logout 1.0 §2, §3). The OP needed nothing for it: a verified hint ends the session and redirects at once, an unverified request goes through the confirmation page, every refusal is the `Request refused` page. Eight modules end in `REVIEW`, the screenshot of the page shown.

### Key rotation

`oidcc-server-rotate-keys` is the one module of `oidcc-dynamic-certification-test-plan` the OP answers (the rest of that plan wants dynamic client registration and request URIs), and the external judge of the key rotation of spike 2. The suite has no plan for a single module, so `castor conformance` creates it on its own through `/api/runner`, with the configuration and the variant `server_metadata=discovery`, the only one it takes. The module reads the JWK Set at its creation and then waits for the operator to rotate the keys before it is started; the task runs `heidi:keys:rotate --now` on the OP in the operator's place, then starts it. The module reads the JWK Set again and passes when a new key is there and one of the former keys still is: the new key signs at once, the one that signed retires over its window (architecture §3.3). A run therefore leaves one more key in the JWK Set until that window closes. The page of the module is its log; there is no plan page.

The other plans of the suite are for what the OP does not have: `implicit`, `hybrid` and their `formpost` variants (decision 0006), `dynamic` (registration, `request_uri`), the back-channel and front-channel logout plans, `session-management` (`check_session_iframe`) and `3rdparty-init-login`.

### Running them

`castor conformance` fills the placeholders of `tests/conformance/configuration.json` from those values, creates each plan through the API of the suite, runs every module (or those named by `--module`, a repeatable substring) and prints one result per module with the failures and warnings of its log, then a summary with the suite version and the URL of each plan page. The scripted browser of the suite signs in and consents by itself, following the `browser` section of the configuration; see `tests/conformance/README.md` for how it reaches the OP and the callback of the suite from inside its container.

Certification itself (the right to display the mark, the public listing) is submitted on https://www.certification.openid.net/ and is paid; testing there is free but needs an OP reachable from the Internet. `castor conformance --suite https://www.certification.openid.net` with `CONFORMANCE_TOKEN` in the environment runs the same plans there.
