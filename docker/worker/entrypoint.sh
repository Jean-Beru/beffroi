#!/bin/sh
# Entrypoint of the worker container: what the consumer of the messages needs from the machine around it,
# then the consumer itself. Two things, both of them about reaching someone outside this container.
#
# The address of the host, for the second instance of oidc-demo ("castor demo --logout-others", issue
# #137): curl resolves every name ending in ".localhost" to the loopback address of whoever asks, without
# reading /etc/hosts, so from in here a client registered on such a name is this container. The address
# docker wrote for the gateway of the host (extra_hosts of compose.yaml) is read here and given to the
# HTTP client of the application as its "resolve" option (config/packages/dev/framework.yaml).
#
# The certificate of the conformance suite, when the suite is up (issue #141): the back-channel logout plan
# has the OP post a logout token to the URI the suite gives its clients, which names localhost:8443; the
# sidecar of compose.yaml brings that port here, and the step this sources is what makes its certificate
# verifiable. It is shared with the op container, which reads the sector identifier documents of the
# Dynamic plan from the same address (issue #363).
set -eu

BEFFROI_DEMO_HOST_IP=$(getent ahostsv4 demo.localhost 2>/dev/null | head -1 | cut -d' ' -f1)
if [ -n "${BEFFROI_DEMO_HOST_IP}" ]; then
	export BEFFROI_DEMO_HOST_IP
	echo "The host answers on ${BEFFROI_DEMO_HOST_IP} for demo.localhost"
fi

CONFORMANCE_TRUST_COSTS="the back-channel logout plan will not receive its token"
export CONFORMANCE_TRUST_COSTS
. /entrypoint/trust-nginx.sh

exec php bin/console messenger:consume "$@"
