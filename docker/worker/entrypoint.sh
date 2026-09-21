#!/bin/sh
# Entrypoint of the worker container: what the consumer of the messages needs from the machine around it,
# then the consumer itself. Two things, both of them about reaching someone outside this container.
#
# The address of the host, for the second instance of oidc-demo ("castor demo --logout-others", issue
# #137): curl resolves every name ending in ".localhost" to the loopback address of whoever asks, without
# reading /etc/hosts, so from in here a client registered on such a name is this container. The address
# docker wrote for the gateway of the host (extra_hosts of compose.yaml) is read here and given to the
# HTTP client of the application as its "resolve" option (config/packages/framework.yaml).
#
# The certificate of the conformance suite, when the suite is up (issue #141): its nginx signs it itself
# and regenerates it with its image, so it is fetched the way tests/conformance/server-entrypoint.sh
# fetches it for the JVM of the suite, and added to the trust store of this container. The back-channel
# logout plan has the OP post a logout token to the URI the suite gives its clients, which names
# localhost:8443; the sidecar of compose.yaml brings that port here, and this is what makes its
# certificate verifiable. Nothing of it runs when the suite is not there.
set -eu

HEIDI_DEMO_HOST_IP=$(getent ahostsv4 demo.localhost 2>/dev/null | head -1 | cut -d' ' -f1)
if [ -n "${HEIDI_DEMO_HOST_IP}" ]; then
	export HEIDI_DEMO_HOST_IP
	echo "The host answers on ${HEIDI_DEMO_HOST_IP} for demo.localhost"
fi

NGINX_HOST=${CONFORMANCE_NGINX_HOST:-conformance-nginx}
NGINX_CERT=/usr/local/share/ca-certificates/conformance-nginx.crt
if getent hosts "${NGINX_HOST}" >/dev/null 2>&1; then
	i=0
	while [ "$i" -lt 30 ]; do
		openssl s_client -connect "${NGINX_HOST}:8443" -showcerts </dev/null 2>/dev/null \
			| openssl x509 -outform PEM > "${NGINX_CERT}" 2>/dev/null && [ -s "${NGINX_CERT}" ] && break
		i=$((i + 1))
		echo "Waiting for the certificate of the suite's nginx at ${NGINX_HOST}:8443 ($i/30)..."
		sleep 2
	done
	if [ -s "${NGINX_CERT}" ] && update-ca-certificates >/dev/null 2>&1; then
		echo "Certificate of the suite's nginx trusted by this container"
	else
		rm -f "${NGINX_CERT}"
		echo "Could not trust the certificate of the suite's nginx; the back-channel logout plan will not receive its token" >&2
	fi
fi

exec php bin/console messenger:consume "$@"
