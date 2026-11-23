<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryJwsSigner;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryKeyPairGenerator;
use Beffroi\Core\Bridge\Key\OpenedKeys;
use Beffroi\Core\Bridge\Key\SealedKeyProvider;
use Beffroi\Core\Bridge\KeyManagement\EnvelopeKeySealer;
use Beffroi\Core\Domain\Key\GeneratedKeyPair;
use Beffroi\Core\Domain\Key\OpenedSigningKeyInterface;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use function sodium_crypto_aead_xchacha20poly1305_ietf_keygen;
use Symfony\Component\KeyManagement\EnvelopeEncrypter;
use Symfony\Component\KeyManagement\KeyLoader\InMemoryKeyLoader;
use Symfony\Component\KeyManagement\Local\SodiumKms;

final class Keys
{
    public const string KMS_KEY_ID = 'signing-keys';

    private static ?GeneratedKeyPair $pair = null;

    private static ?GeneratedKeyPair $otherPair = null;

    private static ?GeneratedKeyPair $encryptionPair = null;

    private static ?GeneratedKeyPair $otherEncryptionPair = null;

    private static ?GeneratedKeyPair $applicationServerPair = null;

    private static ?GeneratedKeyPair $otherApplicationServerPair = null;

    private static ?GeneratedKeyPair $messagePair = null;

    private static ?GeneratedKeyPair $otherMessagePair = null;

    private static ?EnvelopeEncrypter $envelopes = null;

    private static ?EnvelopeKeySealer $sealer = null;

    public static function pair(): GeneratedKeyPair
    {
        return self::$pair ??= new JwtLibraryKeyPairGenerator(Algorithms::everyUse())->generate(Algorithms::rs256());
    }

    public static function otherPair(): GeneratedKeyPair
    {
        return self::$otherPair ??= new JwtLibraryKeyPairGenerator(Algorithms::everyUse())->generate(Algorithms::rs256());
    }

    public static function encryptionPair(): GeneratedKeyPair
    {
        return self::$encryptionPair ??= new JwtLibraryKeyPairGenerator(Algorithms::everyUse())->generate(Algorithms::ecdhEsA256Kw());
    }

    public static function otherEncryptionPair(): GeneratedKeyPair
    {
        return self::$otherEncryptionPair ??= new JwtLibraryKeyPairGenerator(Algorithms::everyUse())->generate(Algorithms::ecdhEsA256Kw());
    }

    /**
     * RFC 8292 §2
     */
    public static function applicationServerPair(): GeneratedKeyPair
    {
        return self::$applicationServerPair ??= new JwtLibraryKeyPairGenerator(Algorithms::everyUse())->generate(Algorithms::vapid());
    }

    public static function otherApplicationServerPair(): GeneratedKeyPair
    {
        return self::$otherApplicationServerPair ??= new JwtLibraryKeyPairGenerator(Algorithms::everyUse())->generate(Algorithms::vapid());
    }

    /**
     * Decision 0020
     */
    public static function messagePair(): GeneratedKeyPair
    {
        return self::$messagePair ??= new JwtLibraryKeyPairGenerator(Algorithms::everyUse())->generate(Algorithms::messageSeal());
    }

    public static function otherMessagePair(): GeneratedKeyPair
    {
        return self::$otherMessagePair ??= new JwtLibraryKeyPairGenerator(Algorithms::everyUse())->generate(Algorithms::messageSeal());
    }

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

    public static function opened(): OpenedKeys
    {
        return new OpenedKeys(self::sealer());
    }

    public static function openedSigningKey(Tenant $tenant): OpenedSigningKeyInterface
    {
        $key = new TenantKey(
            self::pair()->kid,
            $tenant,
            Algorithms::rs256(),
            self::pair()->publicJwk,
            self::sealer()->seal($tenant, self::pair()->privateJwk),
            Fixtures::now(),
            Fixtures::now(),
        );
        $key->activate(Fixtures::now());
        $repository = new InMemoryTenantKeyRepository();
        $repository->save($key);

        return new JwtLibraryJwsSigner(new SealedKeyProvider($repository, self::opened()), Algorithms::all())->open($tenant, Algorithms::rs256());
    }
}
