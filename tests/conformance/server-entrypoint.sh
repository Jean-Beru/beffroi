#!/bin/sh
# Entrypoint of the conformance suite server container: trusts the internal CA of the Caddy
# instance serving the OP (mounted read-only from the caddy_data volume), then starts the suite
# exactly as the upstream image does (gitlab.com/openid/conformance-suite, Dockerfile).
set -eu

CA=/caddy/caddy/pki/authorities/local/root.crt
for i in $(seq 1 60); do
	[ -f "$CA" ] && break
	echo "Waiting for the Caddy internal CA at $CA ($i/60)..."
	sleep 2
done
if [ -f "$CA" ]; then
	keytool -importcert -noprompt -trustcacerts -alias caddy-local -file "$CA" -cacerts -storepass changeit \
		&& echo "Caddy internal CA trusted by the JVM" \
		|| echo "Could not import the Caddy CA; the OP must then be reachable with a publicly trusted certificate" >&2
else
	echo "No Caddy CA found; the OP must be reachable with a publicly trusted certificate" >&2
fi

exec java \
	-D"fintechlabs.base_url=${BASE_URL}" \
	-D"fintechlabs.base_mtls_url=${BASE_MTLS_URL}" \
	-D"spring.data.mongodb.uri=mongodb://${MONGODB_HOST}:27017/test_suite" \
	${SIGNING_KEY:+-D"fintechlabs.signingKey=${SIGNING_KEY}"} \
	${DEPRECATED_SIGNING_KEY:+-D"fintechlabs.deprecatedSigningKey=${DEPRECATED_SIGNING_KEY}"} \
	${PRIVATE_LINK_SIGNING_KEY:+-D"fintechlabs.privateLinkSigningKey=${PRIVATE_LINK_SIGNING_KEY}"} \
	-D"oidc.google.clientid=${OIDC_GOOGLE_CLIENTID}" \
	-D"oidc.google.secret=${OIDC_GOOGLE_SECRET}" \
	-D"oidc.gitlab.clientid=${OIDC_GITLAB_CLIENTID}" \
	-D"oidc.gitlab.secret=${OIDC_GITLAB_SECRET}" \
	${JAVA_EXTRA_ARGS:-} \
	-jar /server/fapi-test-suite.jar \
	-Djdk.tls.maxHandshakeMessageSize=65536
