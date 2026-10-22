# Encrypted responses

The responses whose assertion is encrypted, which `ResponseValidator` reads under the contract of section 6.7 of
`spec/model.md` (rows 38 to 46 of section 9.2, rows 23 and 24 of section 9.3). The encryptions and the signature of a
response over its ciphertext are made by xmlsec1, an implementation that is not this one: xmlsec1 1.3.7 on OpenSSL, in
Alpine 3.22 (`apk add xmlsec`), on 22 October 2026, for the test certificate of the service provider and with the test
key of the identity provider, both under `../keys/`. Each vector is the output of xmlsec1 byte for byte; the hostile
fixtures are each a vector with the one change their name says, written by `derive.php`.

## The data files

`derive.php`, run from this directory, writes the data files from `../behaviour/response-signed-assertion-accepted.xml`:

```
php derive.php data
```

| Data file | What it holds |
|---|---|
| `response-signed-assertion.data.xml` | the response in clear, unsigned, its signed assertion inside a `saml:EncryptedAssertion` and declaring `xmlns:saml` itself: xmlsec1 encrypts an element with the declarations it carries and none it inherits (enc.md section 13), and the exclusive canonical form of the assertion renders that declaration on it wherever it stands, so that its signature is unchanged |
| `response-unsigned-assertion.data.xml` | the same, the signature of the assertion taken off |
| `response-signed-response.data.xml` | the same unsigned assertion, the response carrying the template of an enveloped signature after its `Issuer`, RSA-SHA256 over SHA-256 with the exclusive transform |
| `response-signed-assertion-changed.data.xml` | the first data file, the `NameID` of its signed assertion changed after signing, so that the signature of the assertion no longer holds |
| `response-signed-response-signed-assertion-changed.data.xml` | the same changed assertion under the template of the signature of the response |
| `response-not-an-assertion.data.xml` | the response in clear, its `ID` changed to `_response-inside`, inside the `saml:EncryptedAssertion` in place of the assertion |

`encrypted-data-aes256-gcm.template.xml` is the template of `tests/xml-security/Enc/Fixture/vectors/`: `aes256-gcm`
for the content, the session key under `rsa-oaep-mgf1p`, the certificate in the `KeyInfo` of the `EncryptedKey`, a hint
the validator never reads (enc.md E-6).

## The vectors

From `tests/saml2-model/Fixture/`, the script below in a file `xmlsec.sh` next to it:

```
docker run --rm -v "$PWD:/w" -w /w alpine:3.22 sh xmlsec.sh
```

```
set -e
apk add -q xmlsec
ENC="xmlsec1 --encrypt --lax-key-search --pubkey-cert-pem keys/sp-signing-certificate.pem --session-key aes-256-gcm"
ID="--id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion --node-id _assertion"
$ENC $ID --xml-data encrypted/response-signed-assertion.data.xml \
    --output encrypted/response-encrypted-signed-assertion-accepted.xml encrypted/encrypted-data-aes256-gcm.template.xml
$ENC $ID --xml-data encrypted/response-unsigned-assertion.data.xml \
    --output encrypted/response-encrypted-unsigned-assertion-refused.xml encrypted/encrypted-data-aes256-gcm.template.xml
$ENC $ID --xml-data encrypted/response-signed-response.data.xml \
    --output /tmp/response-signed-response.encrypted.xml encrypted/encrypted-data-aes256-gcm.template.xml
xmlsec1 --sign --lax-key-search --privkey-pem keys/idp-signing-key.pem \
    --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:Response \
    --output encrypted/response-signed-over-encrypted-assertion-accepted.xml /tmp/response-signed-response.encrypted.xml
$ENC --node-xpath "/*/*[local-name()='EncryptedAssertion']/*" --xml-data encrypted/response-not-an-assertion.data.xml \
    --output encrypted/response-encrypted-not-an-assertion-refused.xml encrypted/encrypted-data-aes256-gcm.template.xml
$ENC $ID --xml-data encrypted/response-signed-assertion-changed.data.xml \
    --output encrypted/response-encrypted-assertion-changed-after-signing-refused.xml encrypted/encrypted-data-aes256-gcm.template.xml
$ENC $ID --xml-data encrypted/response-signed-response-signed-assertion-changed.data.xml \
    --output /tmp/response-signed-response-changed.encrypted.xml encrypted/encrypted-data-aes256-gcm.template.xml
xmlsec1 --sign --lax-key-search --privkey-pem keys/idp-signing-key.pem \
    --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:Response \
    --output encrypted/response-signed-over-encrypted-assertion-changed-after-signing-refused.xml \
    /tmp/response-signed-response-changed.encrypted.xml
```

And the checks, in the same container: xmlsec1 decrypts each vector to the bytes of its data file, and verifies the
signature of the response over the ciphertext.

```
DEC="xmlsec1 --decrypt --lax-key-search --privkey-pem keys/sp-signing-key.pem"
$DEC --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion \
    encrypted/response-encrypted-signed-assertion-accepted.xml | diff encrypted/response-signed-assertion.data.xml -
$DEC encrypted/response-encrypted-unsigned-assertion-refused.xml | diff encrypted/response-unsigned-assertion.data.xml -
$DEC encrypted/response-encrypted-not-an-assertion-refused.xml | diff encrypted/response-not-an-assertion.data.xml -
$DEC --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion \
    encrypted/response-encrypted-assertion-changed-after-signing-refused.xml \
    | diff encrypted/response-signed-assertion-changed.data.xml -
for f in response-signed-over-encrypted-assertion-accepted.xml \
    response-signed-over-encrypted-assertion-changed-after-signing-refused.xml; do
    xmlsec1 --verify --lax-key-search --pubkey-cert-pem keys/idp-signing-certificate.pem \
        --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:Response "encrypted/$f"
done
```

The vectors of the changed assertion were written on 22 October 2026 too, after the others, by their own commands
above; xmlsec1 refuses the signature of the assertion they decrypt to (`REFERENCE`), as the validator does.

The session key and the IV are drawn at every run, so a run writes other ciphertexts: the committed vectors are those
of 22 October 2026.

| Vector | Serves |
|---|---|
| `response-encrypted-signed-assertion-accepted.xml` | §9.3 row 23: read with the key of the service provider as the same assertion in clear |
| `response-signed-over-encrypted-assertion-accepted.xml` | §9.3 row 24: the assertion without a signature, covered by the response's over its ciphertext |
| `response-encrypted-unsigned-assertion-refused.xml` | §9.2 row 40: nothing covers the assertion, `SignatureRequired` |
| `response-encrypted-not-an-assertion-refused.xml` | §9.2 row 41: the plaintext is a `samlp:Response` |
| `response-encrypted-assertion-changed-after-signing-refused.xml` | §9.2 row 46: the assertion's own signature fails once decrypted, `DigestMismatch` |
| `response-signed-over-encrypted-assertion-changed-after-signing-refused.xml` | §9.2 row 46: the same under a response whose signature over the ciphertext holds |

## The hostile fixtures

`derive.php`, run from this directory once the vectors are written, each replacement refused unless the text it
replaces is found exactly once:

```
php derive.php hostile
```

| Fixture | Made from | Serves |
|---|---|---|
| `response-encrypted-ciphertext-altered-refused.xml` | the first vector, the first byte of the ciphertext, right after the IV, flipped | §9.2 row 38, `DecryptionFailed` |
| `response-encrypted-tag-truncated-refused.xml` | the first vector, the last byte of the cipher value cut, so that the tag is 15 bytes and the last 16 do not verify | §9.2 row 38, `DecryptionFailed` |
| `response-signed-over-encrypted-assertion-ciphertext-altered-refused.xml` | the signed vector, the same byte flipped | §9.2 row 39, `DigestMismatch` before any decryption |
| `response-encrypted-without-issuer-refused.xml` | the first vector without the `Issuer` of the response | §9.2 row 42, E17, refused at step 2 |
| `response-encrypted-assertion-empty-refused.xml`, `response-encrypted-assertion-two-encrypted-data-refused.xml` | the first vector, its `saml:EncryptedAssertion` emptied, then holding its `xenc:EncryptedData` twice | §9.2 row 43 |
| `response-encrypted-two-encrypted-assertions-refused.xml` | the first vector, its `saml:EncryptedAssertion` twice | §9.2 row 43 |
| `response-encrypted-next-to-an-assertion-refused.xml` | the first vector, the signed assertion in clear of `../behaviour/response-signed-assertion-accepted.xml` after its `saml:EncryptedAssertion` | §9.2 row 43 |
| `response-encrypted-in-a-failure-refused.xml` | the first vector, its status `Responder` | §9.2 row 43 |
| `response-encrypted-key-as-a-sibling-refused.xml` | the first vector, its `xenc:EncryptedKey` moved out of the `ds:KeyInfo`, next to the `xenc:EncryptedData` | §9.2 row 44 |

The third case of row 38, the wrong key, needs no fixture: the first vector read with the test key of the identity
provider.
