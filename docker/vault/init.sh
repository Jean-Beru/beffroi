#!/bin/sh
# Prepares a Vault server for the OP (issue #57): the Transit engine, the key of the tenant and the policy
# of the credential the OP holds. Runs with the root token of the dev server, the one credential that never
# reaches the OP: "castor provision --kms vault" mints a token under the policy for it. The vault container
# of compose.yaml runs it at every start.
#
# Idempotent, so that the server can be restarted at will: the engine is enabled once, writing a key that
# exists is a no-op for Vault, writing a policy replaces it with the same text.
set -eu

: "${BEFFROI_TENANT_SLUG:=default}"
KEY="beffroi-${BEFFROI_TENANT_SLUG}"

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

# What the OP may do, and nothing else (beffroi-op.hcl, next to this script).
vault policy write beffroi-op "$(dirname "$0")/beffroi-op.hcl" >/dev/null

# The audit device, on the standard output of the container, so that the log of this container says what it
# was asked for. A dev server has none until it is asked for one, and a production Vault has one: it is
# where the count of the third success criterion of spike 8 is read, one opening per data key and per thread
# and never one per row (decision 0018, "castor login-cost"), and a count read in the application would be
# a count the application decides. Sensitive values are hashed, which is the default: what is counted is
# the path and the policy of the token, never what crossed. Idempotent, the device being enabled once.
if ! vault audit list -format=json 2>/dev/null | grep -q '"file/"'; then
    vault audit enable file file_path=stdout >/dev/null
fi

echo "Vault ready: key ${KEY}, policy beffroi-op, audit device on stdout"
vault read -format=json "transit/keys/${KEY}" | grep -E '"(name|type|derived|exportable|allow_plaintext_backup|deletion_allowed|latest_version)"'
