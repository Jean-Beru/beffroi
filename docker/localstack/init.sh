#!/bin/sh
# Prepares a LocalStack KMS for the OP (issue #58): the master key of the tenant under the alias the DSN
# names, alias/heidi-<slug>. LocalStack runs it once ready (/etc/localstack/init/ready.d), at every start,
# the community edition keeping nothing across a restart; the CI runs it with the AWS CLI against a service
# container. Idempotent: a key whose alias resolves is left alone, a key is never deleted here.
#
# What a real account does with the key policy (Encrypt refused, GenerateDataKey and Decrypt under the alias
# only, no export, no deletion without a waiting period) has no equivalent in LocalStack, which enforces no
# IAM in this edition: it is documented, not replayed.
set -eu

: "${HEIDI_TENANT_SLUG:=default}"
: "${KMS_ENDPOINT_URL:=http://localhost:4566}"
: "${KMS_REGION:=eu-west-3}"
# The pair LocalStack accepts; a real account takes them from the DSN or from the provider chain of async-aws.
# The region is the one of the DSN, whatever the image sets for itself: a key lives in one region.
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
export AWS_DEFAULT_REGION="${KMS_REGION}"
export AWS_PAGER=""
ALIAS="alias/heidi-${HEIDI_TENANT_SLUG}"

kms() {
    aws --endpoint-url "${KMS_ENDPOINT_URL}" kms "$@"
}

echo "Waiting for KMS at ${KMS_ENDPOINT_URL} ..."
until kms list-aliases >/dev/null 2>&1; do
    sleep 1
done

if kms describe-key --key-id "${ALIAS}" >/dev/null 2>&1; then
    echo "KMS ready: ${ALIAS} exists"
else
    # The master key of the tenant: symmetric, for encryption only (it wraps the data key of every envelope
    # and nothing else, the KMS keeps, it does not sign). The alias is what the OP names, so that a rotation
    # of the master key (a new key behind the same alias) changes nothing in its configuration.
    KEY_ID=$(kms create-key --key-spec SYMMETRIC_DEFAULT --key-usage ENCRYPT_DECRYPT --description "Heidi: master key of tenant ${HEIDI_TENANT_SLUG}" --query KeyMetadata.KeyId --output text)
    kms create-alias --alias-name "${ALIAS}" --target-key-id "${KEY_ID}"
    echo "KMS ready: ${ALIAS} created"
fi

kms describe-key --key-id "${ALIAS}" --query 'KeyMetadata.{KeyId:KeyId,KeySpec:KeySpec,KeyUsage:KeyUsage,KeyState:KeyState}' --output table
