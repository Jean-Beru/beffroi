# OpenID conformance suite

The suite runs locally from the prebuilt images of `registry.gitlab.com/openid/conformance-suite`, under the `conformance` profile of the root `compose.yaml`:

```bash
castor start --conformance     # OP on https://op.localhost, suite on https://localhost:8443
castor conformance             # the whole plan; --module oidcc-server for one (repeatable, substring)
castor logs conformance-server
```

`server-entrypoint.sh` replaces the entrypoint of the suite image for one reason: before starting the suite exactly as the upstream image does, it makes the JVM trust two certificates. The internal CA of the Caddy instance serving the OP, so that the suite calls `https://op.localhost` like a browser does; and the self-signed certificate of the suite's own nginx, because the scripted browser of the suite runs inside that JVM and follows the redirect of the OP to `https://localhost:8443/test/a/heidi/callback`. Inside the container, `localhost` is the container: the `conformance-redirector` sidecar of `compose.yaml` shares its network namespace and forwards the loopback port 8443 to nginx (the suite does the same with `fintechlabs.startredir` and a `redir` binary the prebuilt image does not ship).

The suite version is pinned (`CONFORMANCE_SUITE_VERSION`, `CONFORMANCE_NGINX_VERSION` in `compose.yaml`). Certification results must name the version they were produced with; `castor conformance` prints it with the summary.

## Test plan of spike 1

`oidcc-basic-certification-test-plan`, created with the variants `server_metadata=discovery` and `client_registration=static_client`. The plan is a fixed list of modules, each with its own variant: every one runs with `client_auth_type=client_secret_basic` except `oidcc-server-client-secret-post`, and all with `response_type=code`, `response_mode=default`. Three registered clients serve them: `client` and `client2` (`client_secret_basic`, the second one is the wrong client of some modules) and `client_secret_post` (the one module that authenticates that way). The OP registers them in `apps/op/config/packages/heidi.yaml` as `conformance-basic`, `conformance-basic-second` and `conformance-post`, with the alias `heidi` in their redirect URIs (`https://localhost:8443/test/a/heidi/callback`) and `requires_pkce: false`, because the profile sends no `code_challenge` (decision 0008 of the design repository); `castor provision` generates their secrets into `apps/op/.env.local`.

`basic-op.json` is the plan configuration. It carries no secret: `castor conformance` fills its `{PLACEHOLDERS}` from the environment of the application (`HEIDI_ISSUER`, the three `CONFORMANCE_*_SECRET`, `HEIDI_DEV_USER_PASSWORD`) and from the development user (`HEIDI_DEV_USERNAME`), then creates the plan through the API of the suite, runs its modules one after the other (the alias makes them exclusive) and prints the result of each with the failures and warnings of its log, then a summary and the URL of the plan. The exit code is 1 when a module is `FAILED`, `INTERRUPTED` or `TIMEOUT`; `WARNING` and `REVIEW` are for a human to read on the plan page before anything is submitted, `SKIPPED` is the suite's own choice.

The `browser` section of the configuration drives the scripted browser of the suite (HtmlUnit, see the BrowserControl page of the suite's wiki): on the login page it fills `#username` and `#password` and submits, on the consent page it clicks `button[name=answer][value=allow]`, both optional because a module may find the user signed in or the consent given, then it waits for `#submission_complete` on the callback of the suite. The `override` section adapts it for the modules that expect an error page on the OP instead of a redirect (`oidcc-ensure-registered-redirect-uri`, `oidcc-ensure-request-object-with-redirect-uri`: the text of the page fills the screenshot placeholder of the module, hence a `REVIEW` result) and for those that need a second login (`oidcc-prompt-login`, `oidcc-max-age-1`). A module the browser cannot finish waits for a human: the task prints the URL the suite exposes and waits up to five minutes.

Every run is recorded in the journal of `spikes/01-conformite/README.md` of the documentation repository, with the suite version.
