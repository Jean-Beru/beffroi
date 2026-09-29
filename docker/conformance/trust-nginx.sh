# The certificate of the conformance suite's nginx, added to the trust store of whichever container sources
# this (issues #141, #363). Its nginx signs it itself and regenerates it with its image, so it is fetched
# the way tests/conformance/server-entrypoint.sh fetches it for the JVM of the suite.
#
# Two containers of the stack reach the suite over HTTPS, and both do it at an address that names
# localhost:8443, which a sidecar of compose.yaml carries into their network namespace:
#
#   - the worker posts a logout token to the URI the suite gives its clients (Back-Channel Logout 1.0 §2.5);
#   - the op container reads the document behind a "sector_identifier_uri" the suite serves from the module
#     itself (OIDC Registration §5), when a client of the Dynamic plan registers.
#
# What tells this apart from a stack without the suite is CONFORMANCE_NGINX_HOST, which "castor start
# --conformance" sets and nothing else does: the name is not looked up to find out whether the suite is
# there, because the op container starts before the suite does and would find nothing. Nothing of this
# runs when the variable is empty, which is every ordinary start.
#
# The caller says what a failure costs it (CONFORMANCE_TRUST_COSTS), the two containers losing two
# different things and neither of them saying so anywhere else.

if [ -n "${CONFORMANCE_NGINX_HOST:-}" ]; then
	CONFORMANCE_NGINX_CERT=/usr/local/share/ca-certificates/conformance-nginx.crt
	i=0
	while [ "$i" -lt 30 ]; do
		openssl s_client -connect "${CONFORMANCE_NGINX_HOST}:8443" -showcerts </dev/null 2>/dev/null \
			| openssl x509 -outform PEM > "${CONFORMANCE_NGINX_CERT}" 2>/dev/null && [ -s "${CONFORMANCE_NGINX_CERT}" ] && break
		i=$((i + 1))
		echo "Waiting for the certificate of the suite's nginx at ${CONFORMANCE_NGINX_HOST}:8443 ($i/30)..."
		sleep 2
	done
	if [ -s "${CONFORMANCE_NGINX_CERT}" ] && update-ca-certificates >/dev/null 2>&1; then
		echo "Certificate of the suite's nginx trusted by this container"
	else
		rm -f "${CONFORMANCE_NGINX_CERT}"
		echo "Could not trust the certificate of the suite's nginx; ${CONFORMANCE_TRUST_COSTS:-what this container reads from the suite over HTTPS will fail}" >&2
	fi
fi
