#!/bin/sh
# Entrypoint of the op container: the one thing this container needs from the machine around it before the
# image sets the application up, then the image doing exactly what it does without this file.
#
# The certificate of the conformance suite, when the suite is up (issue #363): the registration endpoint
# reads the document behind a "sector_identifier_uri" (OIDC Registration §5), and the module of the Dynamic
# plan that judges it serves that document from the suite itself, at an address naming localhost:8443. The
# sidecar of compose.yaml brings that port into this namespace, and this is what makes its certificate
# verifiable. Nothing of it runs when the suite is not up.
#
# The chain is the other way round from the worker's: there the script runs behind docker-entrypoint and
# ends in the consumer, here it runs in front of it and ends in it, because everything docker-entrypoint
# does for this container (the install, the wait on the database, the migrations, the stylesheet) it only
# does when the command it is given starts with "frankenphp".
set -eu

CONFORMANCE_TRUST_COSTS="the sector identifier documents the Dynamic plan serves will not be read"
export CONFORMANCE_TRUST_COSTS
. /entrypoint/trust-nginx.sh

exec docker-entrypoint "$@"
