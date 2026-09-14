# Conformance suite

The OpenID Foundation conformance suite is the external judge of spike 1. It runs locally from the prebuilt images of `registry.gitlab.com/openid/conformance-suite`, pinned by version in `compose.yaml`.

```bash
castor start --conformance
castor logs conformance-server
```

Then open https://localhost:8443 (self-signed certificate of the suite's nginx).

## How the suite reaches the OP

- The `op` service has the network alias `op.localhost`, so the suite container resolves it like your browser does.
- Caddy issues the OP certificate from its internal CA. The suite container starts with `tests/conformance/server-entrypoint.sh`, which imports that CA into the JVM truststore before launching the suite exactly as the upstream image does. Everything else in the entrypoint is the upstream command line.
- Verified: a Java `HttpsURLConnection` from the suite container to `https://op.localhost` completes the TLS handshake.

## Gotchas met while wiring it

- The MongoDB property of the jar is `spring.data.mongodb.uri`.
- `SPRING_PROFILES_ACTIVE=dev` avoids the suite login, but the Google and GitLab OAuth registrations must be non-empty placeholders or Spring refuses to start. This mirrors the official `docker-compose-prebuilt.yml`.
- The nginx image proxies to `http://server:8080`: the server service needs the network alias `server`.

## The test plan of spike 1

`oidcc-basic-certification-test-plan`, variants `client_auth_type=client_secret_basic` and `client_secret_post`, `response_type=code`, `response_mode=default`. The plan needs two registered clients; the second is used by the tests that check the behaviour with a wrong client. `castor conformance` creates and runs the plan through the suite API once the OP registers clients.

Certification itself (the right to display the mark, the public listing) is submitted on https://www.certification.openid.net/ and is paid; testing there is free but needs an OP reachable from the Internet.
