<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use CBOR\ByteStringObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\UnsignedIntegerObject;
use function is_array;
use function is_string;
use LogicException;
use const OPENSSL_ALGO_SHA1;
use const OPENSSL_KEYTYPE_RSA;
use function openssl_pkey_get_details;
use function openssl_pkey_new;
use function openssl_sign;
use OpenSSLAsymmetricKey;

/**
 * An RSA key signing in RS1, RSASSA-PKCS1-v1_5 with SHA-1 (RFC 8812 §2, COSE -65535): what a TPM that still
 * signs with it creates, and what only the FIDO2 server API of the conformance tools offers.
 */
final readonly class Rs1SoftwareKey implements SoftwareCredentialKey
{
    private OpenSSLAsymmetricKey $key;

    public function __construct()
    {
        $key = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        if ($key === false) {
            throw new LogicException('OpenSSL could not generate an RSA key.');
        }
        $this->key = $key;
    }

    public function algorithm(): int
    {
        return -65535;
    }

    public function cosePublicKey(): string
    {
        $details = openssl_pkey_get_details($this->key);
        $rsa = is_array($details) && is_array($details['rsa'] ?? null) ? $details['rsa'] : [];
        $modulus = $rsa['n'] ?? null;
        $exponent = $rsa['e'] ?? null;
        if (! is_string($modulus) || ! is_string($exponent)) {
            throw new LogicException('OpenSSL could not describe the key.');
        }

        // RFC 8230 §4: kty RSA (1: 3), alg RS1 (3: -65535), n (-1), e (-2)
        return (string) MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(3)),
            MapItem::create(UnsignedIntegerObject::create(3), NegativeIntegerObject::create($this->algorithm())),
            MapItem::create(NegativeIntegerObject::create(-1), ByteStringObject::create($modulus)),
            MapItem::create(NegativeIntegerObject::create(-2), ByteStringObject::create($exponent)),
        ]);
    }

    public function sign(string $data): string
    {
        if (! openssl_sign($data, $signature, $this->key, OPENSSL_ALGO_SHA1) || ! is_string($signature)) {
            throw new LogicException('OpenSSL could not sign.');
        }

        return $signature;
    }
}
