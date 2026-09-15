<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Fixture;

use Heidi\Core\Bridge\JwtFramework\JwtFrameworkKeyPairGenerator;
use Heidi\Core\Bridge\KeyManagement\EnvelopeKeySealer;
use Heidi\Core\Domain\Key\GeneratedKeyPair;
use Heidi\Core\Domain\Key\SignatureAlgorithm;
use function sodium_crypto_aead_xchacha20poly1305_ietf_keygen;
use Symfony\Component\KeyManagement\EnvelopeEncrypter;
use Symfony\Component\KeyManagement\KeyLoader\InMemoryKeyLoader;
use Symfony\Component\KeyManagement\Local\SodiumKms;

/**
 * Real keys and a real (local) KMS, generated once per process: RSA generation is slow and tests only need
 * a key that works.
 */
final class Keys
{
    public const string KMS_KEY_ID = 'signing-keys';

    private static ?GeneratedKeyPair $pair = null;

    private static ?GeneratedKeyPair $otherPair = null;

    private static ?EnvelopeKeySealer $sealer = null;

    public static function pair(): GeneratedKeyPair
    {
        return self::$pair ??= new JwtFrameworkKeyPairGenerator(2048)->generate(SignatureAlgorithm::RS256);
    }

    public static function otherPair(): GeneratedKeyPair
    {
        return self::$otherPair ??= new JwtFrameworkKeyPairGenerator(2048)->generate(SignatureAlgorithm::RS256);
    }

    public static function sealer(): EnvelopeKeySealer
    {
        return self::$sealer ??= new EnvelopeKeySealer(new EnvelopeEncrypter(new SodiumKms(new InMemoryKeyLoader([
            self::KMS_KEY_ID => sodium_crypto_aead_xchacha20poly1305_ietf_keygen(),
        ]))), self::KMS_KEY_ID);
    }
}
