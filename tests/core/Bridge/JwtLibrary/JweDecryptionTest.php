<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\JwtLibrary;

use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryJweDecrypter;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryJwsVerifier;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryKeyPairGenerator;
use Beffroi\Core\Bridge\Key\OpenedKeys;
use Beffroi\Core\Bridge\Key\SealedKeyProvider;
use Beffroi\Core\Bridge\KeyManagement\EnvelopeKeySealer;
use Beffroi\Core\Domain\Key\GeneratedKeyPair;
use Beffroi\Core\Domain\Key\KeyAlgorithmInterface;
use Beffroi\Core\Domain\Key\KeyUse;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidJweException;
use Beffroi\Core\Exception\InvalidJwsException;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\EnvelopesThatThrow;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA256KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\Signature\Algorithm\RS256 as JoseRs256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer as JwsCompactSerializer;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\KeyManagement\Exception\RuntimeException as KeyManagementFailure;

/**
 * What a client encrypts to the provider (RFC 7516): the key is the published encryption key its "kid"
 * names, opened by the KMS the way a signing key is. The two uses of a JWK Set never cross: what signs is
 * not offered to open a JWE, and what a client encrypts to is not offered to verify a signature.
 */
final class JweDecryptionTest extends TestCase
{
    private Tenant $tenant;

    private InMemoryTenantKeyRepository $repository;

    private OpenedKeys $opened;

    private SealedKeyProvider $provider;

    private TenantKey $encryption;

    private TenantKey $signing;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->repository = new InMemoryTenantKeyRepository();
        $this->signing = $this->activate(Algorithms::rs256(), Keys::pair());
        $this->encryption = $this->activate(Algorithms::ecdhEsA256Kw(), Keys::encryptionPair());
        $this->opened = Keys::opened();
        $this->provider = new SealedKeyProvider($this->repository, $this->opened);
    }

    /**
     * The acceptance criterion: a JWE made against the key the JWK Set publishes opens.
     */
    #[Test]
    public function aJweMadeAgainstThePublishedKeyOpens(): void
    {
        // Given
        $jwe = self::encryptedTo($this->encryption, '{"iss":"acme-console"}');

        // When
        $payload = $this->decrypter()->decrypt($this->tenant, $jwe);

        // Then
        static::assertSame('{"iss":"acme-console"}', $payload);
    }

    /**
     * The retirement window of an encryption key is what bounds it: past it, the key is out of the JWK Set
     * and what was encrypted to it is not opened any more, and the refusal says so.
     */
    #[Test]
    public function theSameJweIsRefusedOnceTheKeyHasRetired(): void
    {
        // Given
        $jwe = self::encryptedTo($this->encryption, '{"iss":"acme-console"}');
        $this->encryption->startRetiring(Fixtures::now(), Fixtures::now());
        $this->encryption->retire(Fixtures::now());
        $this->repository->save($this->encryption);

        // Then
        $this->expectException(InvalidJweException::class);
        $this->expectExceptionMessageIsOrContains('has retired: what was encrypted to it is not opened any more');

        // When
        $this->decrypter()->decrypt($this->tenant, $jwe);
    }

    /**
     * And what the process had open of that key goes with the refusal: a key out of the JWK Set opens
     * nothing any more, so its private half has no reason to stay.
     */
    #[Test]
    public function theMaterialOfAKeyThatHasRetiredLeavesTheProcess(): void
    {
        // Given
        $jwe = self::encryptedTo($this->encryption, '{"iss":"acme-console"}');
        $opened = $this->provider->decryptionKey($this->tenant, $this->encryption->kid);
        $this->encryption->startRetiring(Fixtures::now(), Fixtures::now());
        $this->encryption->retire(Fixtures::now());
        $this->repository->save($this->encryption);

        // When
        try {
            $this->decrypter()->decrypt($this->tenant, $jwe);
        } catch (InvalidJweException) {
        }

        // Then
        static::assertNotSame($opened, $this->opened->open($this->tenant, $this->encryption));
    }

    /**
     * RFC 7517 §4.2: a key published to sign is never handed out to open a JWE, although the tenant
     * publishes it and the "kid" names it.
     */
    #[Test]
    public function aKeyPublishedToSignDoesNotOpenAJwe(): void
    {
        // Then
        $this->expectException(KeyNotFoundException::class);
        $this->expectExceptionMessageIsOrContains('is published with "use": "sig"; it is not a key that opens a JWE');

        // When
        $this->provider->decryptionKey($this->tenant, $this->signing->kid);
    }

    /**
     * The other way round: a key published to be encrypted to is not among the candidates when a signature
     * is verified, so a JWS naming it is refused although the tenant publishes that "kid".
     */
    #[Test]
    public function aKeyPublishedToBeEncryptedToDoesNotVerifyASignature(): void
    {
        // Given
        $jws = new JwsCompactSerializer()->serialize(
            new JWSBuilder(new AlgorithmManager([new JoseRs256()]))
                ->create()
                ->withPayload('{"sub":"alice"}')
                ->addSignature(new JWK(Keys::pair()->privateJwk), [
                    'alg' => 'RS256',
                    'kid' => $this->encryption->kid,
                ])
                ->build(),
            0,
        );

        // Then
        $this->expectException(InvalidJwsException::class);
        $this->expectExceptionMessageIs('The token names a key this tenant does not publish.');

        // When
        new JwtLibraryJwsVerifier($this->provider, Algorithms::all())->verify($this->tenant, $jws);
    }

    /**
     * The tenant publishes several keys, so the one to open with is named and not guessed (RFC 7516
     * §4.1.6): a set of keys is not a set of keys to try.
     */
    #[Test]
    public function aJweThatNamesNoKeyIsRefused(): void
    {
        // Given
        $jwe = self::encryptedTo($this->encryption, '{}', named: false);

        // Then
        $this->expectException(InvalidJweException::class);
        $this->expectExceptionMessageIs('The token does not name the key it was encrypted to (RFC 7516 section 4.1.6).');

        // When
        $this->decrypter()->decrypt($this->tenant, $jwe);
    }

    /**
     * RFC 8725 §3.1: the "alg" is one of those the provider is wired with, and RSA-OAEP is not one of them.
     */
    #[Test]
    public function anAlgorithmTheProviderIsNotWiredWithIsRefused(): void
    {
        // Given
        $rsa = $this->activate(Algorithms::rsaOaep256(), null);
        $jwe = new CompactSerializer()->serialize(
            new JWEBuilder(new AlgorithmManager([new RSAOAEP(), new A256GCM()]))
                ->create()
                ->withPayload('{}')
                ->withSharedProtectedHeader([
                    'alg' => 'RSA-OAEP',
                    'enc' => 'A256GCM',
                    'kid' => $rsa->kid,
                ])
                ->addRecipient(new JWK([
                    ...$rsa->publicJwk,
                    'alg' => 'RSA-OAEP',
                ]))
                ->build(),
        );

        // Then
        $this->expectException(InvalidJweException::class);
        $this->expectExceptionMessageIs('The token is encrypted to with an algorithm this provider is not wired with.');

        // When
        $this->decrypter()->decrypt($this->tenant, $jwe);
    }

    /**
     * RFC 7516 §4.1.2: so is the "enc", and A128GCM is not wired either.
     */
    #[Test]
    public function aContentEncryptionTheProviderIsNotWiredWithIsRefused(): void
    {
        // Given
        $jwe = new CompactSerializer()->serialize(
            new JWEBuilder(new AlgorithmManager([new ECDHESA256KW(), new A128GCM()]))
                ->create()
                ->withPayload('{}')
                ->withSharedProtectedHeader([
                    'alg' => 'ECDH-ES+A256KW',
                    'enc' => 'A128GCM',
                    'kid' => $this->encryption->kid,
                ])
                ->addRecipient(new JWK($this->encryption->publicJwk))
                ->build(),
        );

        // Then
        $this->expectException(InvalidJweException::class);
        $this->expectExceptionMessageIs('The token encrypts its payload with a method this provider is not wired with.');

        // When
        $this->decrypter()->decrypt($this->tenant, $jwe);
    }

    /**
     * Issue #128: a KMS that does not answer is an outage and not a bad token, so it crosses the decrypter
     * as it came and the integration turns it into a 503 on the path that needed it.
     */
    #[Test]
    public function aKmsThatDoesNotAnswerIsAnOutageAndNotARefusal(): void
    {
        // Given
        $jwe = self::encryptedTo($this->encryption, '{}');
        $decrypter = new JwtLibraryJweDecrypter(
            new SealedKeyProvider(
                $this->repository,
                new OpenedKeys(new EnvelopeKeySealer(new EnvelopesThatThrow(new KeyManagementFailure('the KMS did not answer')), Keys::KMS_KEY_ID)),
            ),
            Algorithms::encryption(),
        );

        // Then
        $this->expectException(KmsUnavailableException::class);

        // When
        $decrypter->decrypt($this->tenant, $jwe);
    }

    /**
     * A tenant publishes one active key per algorithm and per use, so the two live side by side.
     */
    #[Test]
    public function theJwkSetCarriesTheTwoUsesSideBySide(): void
    {
        // When
        $published = $this->provider->publicKeys($this->tenant);

        // Then
        static::assertSame(['sig', 'enc'], [
            $published->find($this->signing->kid)?->publicJwk['use'],
            $published->find($this->encryption->kid)?->publicJwk['use'],
        ]);
        static::assertCount(1, $published->forUse(KeyUse::Signature)->keys);
        static::assertCount(1, $published->forUse(KeyUse::Encryption)->keys);
    }

    private function decrypter(): JwtLibraryJweDecrypter
    {
        return new JwtLibraryJweDecrypter($this->provider, Algorithms::encryption());
    }

    private function activate(KeyAlgorithmInterface $algorithm, ?GeneratedKeyPair $pair): TenantKey
    {
        $pair ??= new JwtLibraryKeyPairGenerator(Algorithms::everyUse())->generate($algorithm);
        $key = new TenantKey(
            $pair->kid,
            $this->tenant,
            $algorithm,
            $pair->publicJwk,
            Keys::sealer()->seal($this->tenant, $pair->privateJwk),
            Fixtures::now(),
            Fixtures::now(),
        );
        $key->activate(Fixtures::now());
        $this->repository->save($key);

        return $key;
    }

    /**
     * A JWE as a client makes one against the JWK Set of the tenant.
     */
    private static function encryptedTo(TenantKey $key, string $payload, bool $named = true): string
    {
        $header = [
            'alg' => $key->algorithm->name(),
            'enc' => 'A256GCM',
        ];
        if ($named) {
            $header['kid'] = $key->kid;
        }

        return new CompactSerializer()->serialize(
            new JWEBuilder(new AlgorithmManager([new ECDHESA256KW(), new A256GCM()]))
                ->create()
                ->withPayload($payload)
                ->withSharedProtectedHeader($header)
                ->addRecipient(new JWK($key->publicJwk))
                ->build(),
        );
    }
}
