<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Fixture;

use Heidi\Core\Bridge\JwtLibrary\JwtLibraryKeyPairGenerator;
use Heidi\Core\Bridge\KeyManagement\EnvelopeKeySealer;
use Heidi\Core\Domain\Key\GeneratedKeyPair;
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

    private static ?EnvelopeEncrypter $envelopes = null;

    private static ?EnvelopeKeySealer $sealer = null;

    public static function pair(): GeneratedKeyPair
    {
        return self::$pair ??= new JwtLibraryKeyPairGenerator(Algorithms::all())->generate(Algorithms::rs256());
    }

    public static function otherPair(): GeneratedKeyPair
    {
        return self::$otherPair ??= new JwtLibraryKeyPairGenerator(Algorithms::all())->generate(Algorithms::rs256());
    }

    /**
     * The one KMS of the suite, under which the signing keys and the secrets of the users are sealed alike.
     */
    public static function envelopes(): EnvelopeEncrypter
    {
        return self::$envelopes ??= new EnvelopeEncrypter(new SodiumKms(new InMemoryKeyLoader([
            self::KMS_KEY_ID => sodium_crypto_aead_xchacha20poly1305_ietf_keygen(),
        ])));
    }

    public static function sealer(): EnvelopeKeySealer
    {
        return self::$sealer ??= new EnvelopeKeySealer(self::envelopes(), self::KMS_KEY_ID);
    }
}
