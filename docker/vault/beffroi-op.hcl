# The policy of the credential the OP holds (architecture §3.3, issue #57): what the keys of the tenant need
# and nothing else. The OP never asks Vault to sign, never reads a key, never exports one.
#
# The envelope of symfony/key-management is opened and sealed with a data key: the OP mints one under the
# Transit key of the tenant (datakey/plaintext), unwraps it later (decrypt), and reads the configuration of
# the key once per process to make sure it was created with derived=true, without which Vault would ignore
# the context that binds a data key to its reference and its scope (the preflight of the bridge).
# It encrypts one thing, a data key it already holds, which a rewrap wraps again under this key (the
# wrapDataKey() of the bridge is transit/encrypt): the private JWK and the sealed values never reach Vault,
# only data keys do. No update on transit/keys: no creation, no rotation, no configuration change, and
# nothing on transit/export nor transit/backup, which the keys refuse anyway (exportable=false,
# allow_plaintext_backup=false, docker/vault/init.sh).
#
# One Transit key per tenant, named beffroi-<slug of the tenant>: a credential for the hosted offer is cut
# from this policy with the slug in place of the wildcard.
path "transit/datakey/plaintext/beffroi-*" {
  capabilities = ["update"]
}

path "transit/decrypt/beffroi-*" {
  capabilities = ["update"]
}

path "transit/encrypt/beffroi-*" {
  capabilities = ["update"]
}

path "transit/keys/beffroi-*" {
  capabilities = ["read"]
}
