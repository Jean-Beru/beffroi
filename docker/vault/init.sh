#!/bin/sh
# Prepares a Vault server for the OP (issue #57): the Transit engine, the key of the tenant and the policy
# of the credential the OP holds. Runs with the root token of the dev server, the one credential that never
# reaches the OP: "castor provision --kms vault" mints a token under the policy for it.
#
# Idempotent, so that the service can be restarted at will: the engine is enabled once, writing a key that
# exists is a no-op for Vault, writing a policy replaces it with the same text.
set -eu

: "${HEIDI_TENANT_SLUG:=default}"
KEY="heidi-${HEIDI_TENANT_SLUG}"

echo "Waiting for Vault at ${VAULT_ADDR} ..."
until vault status >/dev/null 2>&1; do
    sleep 1
done

if ! vault secrets list -format=json | grep -q '"transit/"'; then
    vault secrets enable transit
fi

# The master key of the tenant. derived=true: the envelope carries a context (the AAD that binds it to its
# use and its tenant) and Vault only honours a context on a derived key, it silently ignores it otherwise;
# the bridge refuses to seal under a key that is not derived. Not exportable, no plaintext backup: the key
# material never leaves Vault, whoever asks. Deletion refused: a rotation retires a version, it never
# deletes the key (transit/keys/<name>/rotate, min_decryption_version, transit/rewrap).
vault write -f "transit/keys/${KEY}" type=aes256-gcm96 derived=true exportable=false allow_plaintext_backup=false >/dev/null
vault write "transit/keys/${KEY}/config" deletion_allowed=false >/dev/null

# What the OP may do, and nothing else (heidi-op.hcl, next to this script).
vault policy write heidi-op "$(dirname "$0")/heidi-op.hcl" >/dev/null

echo "Vault ready: key ${KEY}, policy heidi-op"
vault read -format=json "transit/keys/${KEY}" | grep -E '"(name|type|derived|exportable|allow_plaintext_backup|deletion_allowed|latest_version)"'
