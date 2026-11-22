#!/bin/sh
# Prepares the KMS of Floci for the OP (issue #58): the master key of the tenant under the alias the DSN
# names, alias/beffroi-<slug>. Floci runs it once its API is up (/etc/floci/init/ready.d), at every start;
# nothing is kept across a restart in the storage mode of the stack (memory, the default). Idempotent: a key
# whose alias resolves is left alone, a key is never deleted here. A hook that fails stops Floci
# (fail-fast, its own rule, where LocalStack only logged), so the container is never up with no key.
#
# What a real account does with the key policy (Encrypt refused, GenerateDataKey and Decrypt under the alias
# only, no export, no deletion without a waiting period) has no equivalent here: Floci stores grants and key
# policies but evaluates neither on a cryptographic call. It is documented, not replayed.
set -eu

: "${BEFFROI_TENANT_SLUG:=default}"
: "${KMS_ENDPOINT_URL:=http://localhost:4566}"
: "${KMS_REGION:=eu-west-3}"
# The pair Floci accepts (any non-empty one does); a real account takes them from the DSN or from the
# provider chain of async-aws. The region is the one of the DSN, whatever the image sets for itself: a key
# lives in one region.
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
export AWS_DEFAULT_REGION="${KMS_REGION}"
export AWS_PAGER=""
ALIAS="alias/beffroi-${BEFFROI_TENANT_SLUG}"

kms() {
    aws --endpoint-url "${KMS_ENDPOINT_URL}" kms "$@"
}

# The ready phase runs after the HTTP server answers, so this returns at once; the few tries are for a run
# by hand against a container that is still starting. A hook of Floci is given 30 s and a hook that fails
# stops the container, so the loop is bounded rather than infinite.
echo "Waiting for KMS at ${KMS_ENDPOINT_URL} ..."
attempt=0
until kms list-aliases >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "${attempt}" -ge 15 ]; then
        echo "KMS unreachable at ${KMS_ENDPOINT_URL}" >&2
        exit 1
    fi
    sleep 1
done

if kms describe-key --key-id "${ALIAS}" >/dev/null 2>&1; then
    echo "KMS ready: ${ALIAS} exists"
else
    # The master key of the tenant: symmetric, for encryption only (it wraps the data key of every envelope
    # and nothing else, the KMS keeps, it does not sign). The alias is what the OP names, so that a rotation
    # of the master key (a new key behind the same alias) changes nothing in its configuration.
    KEY_ID=$(kms create-key --key-spec SYMMETRIC_DEFAULT --key-usage ENCRYPT_DECRYPT --description "Beffroi: master key of tenant ${BEFFROI_TENANT_SLUG}" --query KeyMetadata.KeyId --output text)
    kms create-alias --alias-name "${ALIAS}" --target-key-id "${KEY_ID}"
    echo "KMS ready: ${ALIAS} created"
fi

kms describe-key --key-id "${ALIAS}" --query 'KeyMetadata.{KeyId:KeyId,KeySpec:KeySpec,KeyUsage:KeyUsage,KeyState:KeyState}' --output table
