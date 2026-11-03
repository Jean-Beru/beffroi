<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use CBOR\ByteStringObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\UnsignedIntegerObject;
use function sodium_crypto_sign_detached;
use function sodium_crypto_sign_keypair;
use function sodium_crypto_sign_publickey;
use function sodium_crypto_sign_secretkey;

/**
 * An Ed25519 key signing in EdDSA (RFC 9053 §2.2, COSE -8), what a hardware key creates when it is asked first.
 */
final readonly class Ed25519SoftwareKey implements SoftwareCredentialKey
{
    private string $keyPair;

    public function __construct()
    {
        $this->keyPair = sodium_crypto_sign_keypair();
    }

    public function algorithm(): int
    {
        return -8;
    }

    public function cosePublicKey(): string
    {
        // RFC 9053 §7.2: kty OKP (1: 1), alg EdDSA (3: -8), crv Ed25519 (-1: 6), x (-2)
        return (string) MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(1)),
            MapItem::create(UnsignedIntegerObject::create(3), NegativeIntegerObject::create($this->algorithm())),
            MapItem::create(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(6)),
            MapItem::create(NegativeIntegerObject::create(-2), ByteStringObject::create(sodium_crypto_sign_publickey($this->keyPair))),
        ]);
    }

    public function sign(string $data): string
    {
        return sodium_crypto_sign_detached($data, sodium_crypto_sign_secretkey($this->keyPair));
    }
}
