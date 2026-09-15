# OpenID conformance suite

The suite runs locally from the prebuilt images of `registry.gitlab.com/openid/conformance-suite`, under the `conformance` profile of the root `compose.yaml`:

```bash
castor start --conformance     # OP on https://op.localhost, suite on https://localhost:8443
castor logs conformance-server
```

`server-entrypoint.sh` replaces the entrypoint of the suite image for one reason: it imports the internal CA of the Caddy instance serving the OP into the JVM truststore before starting the suite, so that the suite can call `https://op.localhost` like a browser does. Everything else is the upstream command line.

The suite version is pinned (`CONFORMANCE_SUITE_VERSION`, `CONFORMANCE_NGINX_VERSION` in `compose.yaml`). Certification results must name the version they were produced with.

## Test plan of spike 1

`oidcc-basic-certification-test-plan`, variants `client_auth_type=client_secret_basic` and `client_secret_post`, `response_type=code`, `response_mode=default`. The plan needs two registered clients; the second one is used by the tests that check the behaviour with a wrong client. The OP registers one pair per variant in `apps/op/config/packages/heidi.yaml` (`conformance-basic` / `conformance-basic-second`, `conformance-post` / `conformance-post-second`), with the alias `heidi` in their redirect URIs (`https://localhost:8443/test/a/heidi/callback`); `castor provision` generates their secrets into `apps/op/.env.local`. The plan configuration lives in `basic-op.json`, and `castor conformance` will create and run the plan through the API of the suite.

Every daily run is recorded in the journal of `spikes/01-conformite/README.md`.
