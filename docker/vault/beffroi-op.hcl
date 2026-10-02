# The policy of the credential the OP holds (architecture §3.3, issue #57): what the sealing of the signing
# keys needs and nothing else. The OP never asks Vault to sign, never reads a key, never exports one.
#
# The envelope of symfony/key-management is opened and sealed with a data key: the OP mints one under the
# Transit key of the tenant (datakey/plaintext), unwraps it later (decrypt), and reads the configuration of
# the key once per process to make sure it was created with derived=true, without which Vault would ignore
# the context that binds an envelope to its tenant (the AAD of the envelope, the preflight of the bridge).
# It never encrypts directly: the private JWK never reaches Vault, only the data key does, so no capability
# on transit/encrypt. No update on transit/keys: no creation, no rotation, no configuration change, and
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

path "transit/keys/beffroi-*" {
  capabilities = ["read"]
}
