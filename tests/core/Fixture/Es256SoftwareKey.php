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
use const OPENSSL_ALGO_SHA256;
use const OPENSSL_KEYTYPE_EC;
use function openssl_pkey_get_details;
use function openssl_pkey_new;
use function openssl_sign;
use OpenSSLAsymmetricKey;
use function str_pad;
use const STR_PAD_LEFT;

/**
 * A P-256 key signing in ES256 (RFC 9053 §2.1), what a platform authenticator and a hardware key create first.
 */
final readonly class Es256SoftwareKey implements SoftwareCredentialKey
{
    private OpenSSLAsymmetricKey $key;

    public function __construct()
    {
        $key = openssl_pkey_new([
            'curve_name' => 'prime256v1',
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ]);
        if ($key === false) {
            throw new LogicException('OpenSSL could not generate a P-256 key.');
        }
        $this->key = $key;
    }

    public function algorithm(): int
    {
        return -7;
    }

    public function cosePublicKey(): string
    {
        $details = openssl_pkey_get_details($this->key);
        $curve = is_array($details) && is_array($details['ec'] ?? null) ? $details['ec'] : [];
        $x = $curve['x'] ?? null;
        $y = $curve['y'] ?? null;
        if (! is_string($x) || ! is_string($y)) {
            throw new LogicException('OpenSSL could not describe the key.');
        }

        // RFC 9053 §7.1.1: kty EC2 (1: 2), alg ES256 (3: -7), crv P-256 (-1: 1), x (-2), y (-3)
        return (string) MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(2)),
            MapItem::create(UnsignedIntegerObject::create(3), NegativeIntegerObject::create($this->algorithm())),
            MapItem::create(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(1)),
            MapItem::create(NegativeIntegerObject::create(-2), ByteStringObject::create(str_pad($x, 32, "\0", STR_PAD_LEFT))),
            MapItem::create(NegativeIntegerObject::create(-3), ByteStringObject::create(str_pad($y, 32, "\0", STR_PAD_LEFT))),
        ]);
    }

    public function sign(string $data): string
    {
        if (! openssl_sign($data, $signature, $this->key, OPENSSL_ALGO_SHA256) || ! is_string($signature)) {
            throw new LogicException('OpenSSL could not sign.');
        }

        return $signature;
    }
}
