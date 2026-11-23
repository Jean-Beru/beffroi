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
use Beffroi\Core\Domain\Encoding\Base64Url;
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
use function explode;
use function implode;
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
use function random_bytes;
use Symfony\Component\KeyManagement\Exception\RuntimeException as KeyManagementFailure;

/**
 * RFC 7516
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

    #[Test]
    public function aKeyThatHasRetiredLeavesTheProcessWhenItsSuccessorOpensAJwe(): void
    {
        // Given
        $opened = $this->provider->decryptionKey($this->tenant, $this->encryption->kid);
        $successor = $this->activate(Algorithms::ecdhEsA256Kw(), Keys::otherEncryptionPair());
        $this->encryption->startRetiring(Fixtures::now(), Fixtures::now());
        $this->encryption->retire(Fixtures::now());
        $this->repository->save($this->encryption);

        // When
        $this->decrypter()->decrypt($this->tenant, self::encryptedTo($successor, '{"iss":"acme-console"}'));

        // Then
        static::assertNotSame($opened, $this->opened->open($this->tenant, $this->encryption));
    }

    /**
     * RFC 7517 §4.2
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
     * RFC 7516 §4.1.6
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
     * RFC 8725 §3.1
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
     * RFC 7516 §4.1.2
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
     * RFC 7516 §4.1.13
     */
    #[Test]
    public function aJweThatMarksAParameterCriticalIsRefused(): void
    {
        // Given
        $jwe = self::encryptedTo($this->encryption, '{}', header: [
            'crit' => ['urn:example:must-understand'],
            'urn:example:must-understand' => true,
        ]);

        // Then
        $this->expectException(InvalidJweException::class);
        $this->expectExceptionMessageIs('The token uses an extension of JOSE this provider does not understand (RFC 7516 section 4.1.13).');

        // When
        $this->decrypter()->decrypt($this->tenant, $jwe);
    }

    /**
     * RFC 7518 §5.3
     */
    #[Test]
    public function aJweWhoseInitializationVectorIsNotTheSizeOfItsContentEncryptionIsRefused(): void
    {
        // Given
        $parts = explode('.', self::encryptedTo($this->encryption, '{}'));
        $parts[2] = Base64Url::encode(random_bytes(16));

        // Then
        $this->expectException(InvalidJweException::class);
        $this->expectExceptionMessageIs('The token cannot be opened as a JWE (RFC 7516 section 5.2).');

        // When
        $this->decrypter()->decrypt($this->tenant, implode('.', $parts));
    }

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
     * @param array<string, mixed> $header
     */
    private static function encryptedTo(TenantKey $key, string $payload, bool $named = true, array $header = []): string
    {
        $header = [
            ...$header,
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
