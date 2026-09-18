<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Bridge\JwtFramework;

use function array_keys;
use function base64_decode;
use function explode;
use Heidi\Core\Bridge\InMemory\InMemorySigningKeyRepository;
use Heidi\Core\Bridge\JwtFramework\JwtFrameworkJwsSigner;
use Heidi\Core\Bridge\JwtFramework\JwtFrameworkJwsVerifier;
use Heidi\Core\Bridge\JwtFramework\JwtFrameworkKeyPairGenerator;
use Heidi\Core\Bridge\Key\SealedKeyProvider;
use Heidi\Core\Domain\Key\SignatureAlgorithm;
use Heidi\Core\Domain\Key\SigningKey;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Exception\InvalidJwsException;
use Heidi\Core\Exception\KeyNotFoundException;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\Keys;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use function json_decode;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;
use function strtr;

final class JwtFrameworkTest extends TestCase
{
    private Tenant $tenant;

    private InMemorySigningKeyRepository $repository;

    private SealedKeyProvider $provider;

    private SigningKey $active;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->repository = new InMemorySigningKeyRepository();
        $this->active = new SigningKey(Keys::pair()->kid, $this->tenant, SignatureAlgorithm::RS256, Keys::pair()->publicJwk, Keys::sealer()->seal($this->tenant, Keys::pair()->privateJwk), Fixtures::now());
        $this->active->activate(Fixtures::now());
        $this->repository->save($this->active);
        $this->provider = new SealedKeyProvider($this->repository, Keys::sealer());
    }

    /**
     * RFC 7638 §3: the kid is the SHA-256 thumbprint of the public key.
     */
    #[Test]
    public function theGeneratorNamesTheKeyByItsThumbprint(): void
    {
        // When
        $pair = Keys::pair();

        // Then
        static::assertSame($pair->kid, new JWK($pair->publicJwk)->thumbprint('sha256'));
        static::assertSame($pair->kid, $pair->publicJwk['kid']);
        static::assertSame($pair->kid, $pair->privateJwk['kid']);
        static::assertNotSame($pair->kid, Keys::otherPair()->kid);
    }

    /**
     * RFC 7517 §4: the public JWK carries kid, alg and use, and no private member.
     */
    #[Test]
    public function theGeneratorProducesAPublicJwkWithoutPrivateMembers(): void
    {
        // When
        $pair = Keys::pair();

        // Then
        static::assertSame('RSA', $pair->publicJwk['kty']);
        static::assertSame('RS256', $pair->publicJwk['alg']);
        static::assertSame('sig', $pair->publicJwk['use']);
        static::assertArrayNotHasKey('d', $pair->publicJwk);
        static::assertArrayHasKey('d', $pair->privateJwk);
    }

    /**
     * RFC 7518 §3.3: at least 2048 bits.
     */
    #[Test]
    public function theGeneratorRefusesKeysUnderTheMinimum(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new JwtFrameworkKeyPairGenerator(1024);
    }

    /**
     * RFC 7515 §7.1 compact serialization, header with alg and kid.
     */
    #[Test]
    public function itSignsWithTheActiveKeyAndNamesItInTheHeader(): void
    {
        // Given
        $signer = new JwtFrameworkJwsSigner($this->provider);

        // When
        $jws = $signer->sign($this->tenant, SignatureAlgorithm::RS256, '{"sub":"alice"}', [
            'typ' => 'at+jwt',
        ]);

        // Then
        [$header] = explode('.', $jws);
        static::assertSame([
            'typ' => 'at+jwt',
            'alg' => 'RS256',
            'kid' => $this->active->kid,
        ], json_decode((string) base64_decode(strtr($header, '-_', '+/'), true), true));
    }

    /**
     * Verified by jwt-framework against the published JWK Set, the way a relying party would.
     */
    #[Test]
    public function theSignatureVerifiesAgainstThePublishedJwks(): void
    {
        // Given
        $jws = new JwtFrameworkJwsSigner($this->provider)
            ->sign($this->tenant, SignatureAlgorithm::RS256, '{"sub":"alice"}');
        $jwks = JWKSet::createFromKeyData($this->provider->publicKeys($this->tenant)->toJwks());

        // When
        $verified = new JWSVerifier(new AlgorithmManager([new RS256()]))->verifyWithKeySet(new CompactSerializer()->unserialize($jws), $jwks, 0);

        // Then
        static::assertTrue($verified);
    }

    #[Test]
    public function theVerifierReturnsThePayloadTheKeyAndTheHeader(): void
    {
        // Given
        $jws = new JwtFrameworkJwsSigner($this->provider)
            ->sign($this->tenant, SignatureAlgorithm::RS256, '{"sub":"alice"}', [
                'typ' => 'at+jwt',
            ]);

        // When
        $verified = new JwtFrameworkJwsVerifier($this->provider)
            ->verify($this->tenant, $jws);

        // Then
        static::assertSame('{"sub":"alice"}', $verified->payload);
        static::assertSame($this->active, $verified->key);
        static::assertSame('at+jwt', $verified->protectedHeader['typ']);
    }

    #[Test]
    public function theCallerCannotOverrideAlgOrKid(): void
    {
        // Given
        $signer = new JwtFrameworkJwsSigner($this->provider);

        // When
        $jws = $signer->sign($this->tenant, SignatureAlgorithm::RS256, 'x', [
            'alg' => 'none',
            'kid' => 'forged',
        ]);

        // Then
        static::assertSame($this->active, new JwtFrameworkJwsVerifier($this->provider)->verify($this->tenant, $jws)->key);
    }

    #[Test]
    public function signingWithoutAnActiveKeyFails(): void
    {
        // Given
        $signer = new JwtFrameworkJwsSigner(new SealedKeyProvider(new InMemorySigningKeyRepository(), Keys::sealer()));

        // Then
        $this->expectException(KeyNotFoundException::class);

        // When
        $signer->sign($this->tenant, SignatureAlgorithm::RS256, 'x');
    }

    /**
     * OIDC Core §10.1.1: what the previous key signed stays verifiable while it is in the JWK Set.
     */
    #[Test]
    public function aRetiringKeyStillVerifies(): void
    {
        // Given
        $this->active->startRetiring(Fixtures::now(), Fixtures::now()->modify('+10 minutes'));
        $jws = self::signWith(Keys::pair()->privateJwk, 'payload');

        // When
        $verified = new JwtFrameworkJwsVerifier($this->provider)
            ->verify($this->tenant, $jws);

        // Then
        static::assertSame($this->active, $verified->key);
    }

    #[Test]
    public function aRetiringKeyNoLongerSigns(): void
    {
        // Given
        $this->active->startRetiring(Fixtures::now(), Fixtures::now()->modify('+10 minutes'));
        $signer = new JwtFrameworkJwsSigner($this->provider);

        // Then
        $this->expectException(KeyNotFoundException::class);

        // When
        $signer->sign($this->tenant, SignatureAlgorithm::RS256, 'x');
    }

    /**
     * A staged key is published so that a cache learns it, and signs nothing until it is activated.
     */
    #[Test]
    public function aStagedKeyDoesNotSign(): void
    {
        // Given
        $repository = new InMemorySigningKeyRepository();
        $repository->save(new SigningKey(Keys::pair()->kid, $this->tenant, SignatureAlgorithm::RS256, Keys::pair()->publicJwk, Keys::sealer()->seal($this->tenant, Keys::pair()->privateJwk), Fixtures::now()));
        $signer = new JwtFrameworkJwsSigner(new SealedKeyProvider($repository, Keys::sealer()));

        // Then
        $this->expectException(KeyNotFoundException::class);

        // When
        $signer->sign($this->tenant, SignatureAlgorithm::RS256, 'x');
    }

    /**
     * A JWS naming a retired kid is refused like one naming a key that never existed.
     */
    #[Test]
    public function aRetiredKeyNoLongerVerifies(): void
    {
        // Given
        $this->active->startRetiring(Fixtures::now(), Fixtures::now());
        $this->active->retire(Fixtures::now());
        $jws = self::signWith(Keys::pair()->privateJwk, 'payload');

        // Then
        $this->expectException(InvalidJwsException::class);

        // When
        new JwtFrameworkJwsVerifier($this->provider)
            ->verify($this->tenant, $jws);
    }

    /**
     * RFC 8725 §3.1 and §3.2: the algorithm comes from the verifier, never from the token; "none" and HMAC
     * are refused whatever the header says.
     */
    #[Test]
    public function itRefusesTokensSignedWithAnotherAlgorithm(): void
    {
        // Given
        $hmac = new JWSBuilder(new AlgorithmManager([new HS256()]))->create()->withPayload('payload')->addSignature(new JWK([
            'kty' => 'oct',
            'k' => rtrim(strtr(base64_encode(str_repeat('k', 32)), '+/', '-_'), '='),
        ]), [
            'alg' => 'HS256',
            'kid' => $this->active->kid,
        ])->build();
        $jws = new CompactSerializer()
            ->serialize($hmac, 0);

        // Then
        $this->expectException(InvalidJwsException::class);

        // When
        new JwtFrameworkJwsVerifier($this->provider)
            ->verify($this->tenant, $jws);
    }

    #[Test]
    public function itRefusesAKeyTheTenantDoesNotPublish(): void
    {
        // Given
        $jws = self::signWith(Keys::otherPair()->privateJwk, 'payload');

        // Then
        $this->expectException(InvalidJwsException::class);

        // When
        new JwtFrameworkJwsVerifier($this->provider)
            ->verify($this->tenant, $jws);
    }

    #[Test]
    public function itRefusesAKeyOfAnotherTenant(): void
    {
        // Given
        $jws = self::signWith(Keys::pair()->privateJwk, 'payload');

        // Then
        $this->expectException(InvalidJwsException::class);

        // When
        new JwtFrameworkJwsVerifier($this->provider)
            ->verify(Fixtures::tenant('other', 'https://id.other.example'), $jws);
    }

    #[Test]
    public function itRefusesATokenWithoutKid(): void
    {
        // Given
        $built = new JWSBuilder(new AlgorithmManager([new RS256()]))->create()->withPayload('payload')->addSignature(new JWK(Keys::pair()->privateJwk), [
            'alg' => 'RS256',
        ])->build();
        $jws = new CompactSerializer()
            ->serialize($built, 0);

        // Then
        $this->expectException(InvalidJwsException::class);

        // When
        new JwtFrameworkJwsVerifier($this->provider)
            ->verify($this->tenant, $jws);
    }

    #[Test]
    public function itRefusesATamperedPayload(): void
    {
        // Given
        [$header, , $signature] = explode('.', self::signWith(Keys::pair()->privateJwk, '{"sub":"alice"}'));
        $forged = $header . '.' . rtrim(strtr(base64_encode('{"sub":"mallory"}'), '+/', '-_'), '=') . '.' . $signature;

        // Then
        $this->expectException(InvalidJwsException::class);

        // When
        new JwtFrameworkJwsVerifier($this->provider)
            ->verify($this->tenant, $forged);
    }

    #[Test]
    public function itRefusesWhatIsNotACompactJws(): void
    {
        // Then
        $this->expectException(InvalidJwsException::class);

        // When
        new JwtFrameworkJwsVerifier($this->provider)
            ->verify($this->tenant, 'not.a.jws.at.all');
    }

    #[Test]
    public function theProviderOpensTheActiveKey(): void
    {
        // When
        $key = $this->provider->activeKey($this->tenant, SignatureAlgorithm::RS256);

        // Then
        static::assertSame(Keys::pair()->privateJwk, $key->privateJwk);
    }

    #[Test]
    public function theProviderOpensAKeyOnce(): void
    {
        // Given
        $first = $this->provider->activeKey($this->tenant, SignatureAlgorithm::RS256);

        // When
        $second = $this->provider->activeKey($this->tenant, SignatureAlgorithm::RS256);

        // Then
        static::assertSame($first, $second);
    }

    /**
     * The opened private half of a key that stopped signing leaves the memory of the provider: the next
     * active key is opened, the previous one is not kept beside it.
     */
    #[Test]
    public function theProviderForgetsAKeyOnceItIsNoLongerActive(): void
    {
        // Given
        $this->provider->activeKey($this->tenant, SignatureAlgorithm::RS256);
        $this->active->startRetiring(Fixtures::now(), Fixtures::now()->modify('+10 minutes'));
        $next = new SigningKey(Keys::otherPair()->kid, $this->tenant, SignatureAlgorithm::RS256, Keys::otherPair()->publicJwk, Keys::sealer()->seal($this->tenant, Keys::otherPair()->privateJwk), Fixtures::now());
        $next->activate(Fixtures::now());
        $this->repository->save($next);

        // When
        $opened = $this->provider->activeKey($this->tenant, SignatureAlgorithm::RS256);

        // Then
        static::assertSame($next, $opened->key);
        $kept = new ReflectionProperty($this->provider, 'opened')
            ->getValue($this->provider);
        static::assertIsArray($kept);
        static::assertSame([Keys::otherPair()->kid], array_keys($kept));
    }

    #[Test]
    public function theProviderPublishesStagedActiveAndRetiringKeys(): void
    {
        // Given
        $retiring = new SigningKey(Keys::otherPair()->kid, $this->tenant, SignatureAlgorithm::RS256, Keys::otherPair()->publicJwk, Keys::sealer()->seal($this->tenant, Keys::otherPair()->privateJwk), Fixtures::now()->modify('-1 day'));
        $retiring->activate(Fixtures::now()->modify('-1 day'));
        $retiring->startRetiring(Fixtures::now(), Fixtures::now()->modify('+10 minutes'));
        $this->repository->save($retiring);
        $staged = new SigningKey('staged-kid', $this->tenant, SignatureAlgorithm::RS256, [
            ...Keys::otherPair()->publicJwk,
            'kid' => 'staged-kid',
        ], 'sealed', Fixtures::now()->modify('+1 minute'));
        $this->repository->save($staged);

        // When
        $published = $this->provider->publicKeys($this->tenant);

        // Then
        static::assertSame([$retiring, $this->active, $staged], $published->keys);
    }

    #[Test]
    public function theProviderPublishesNothingForATenantWithoutKeys(): void
    {
        // When
        $published = $this->provider->publicKeys(Fixtures::tenant('other', 'https://id.other.example'));

        // Then
        static::assertTrue($published->isEmpty());
    }

    /**
     * @param array<string, string> $privateJwk
     */
    private static function signWith(array $privateJwk, string $payload): string
    {
        $jws = new JWSBuilder(new AlgorithmManager([new RS256()]))->create()->withPayload($payload)->addSignature(new JWK($privateJwk), [
            'alg' => 'RS256',
            'kid' => $privateJwk['kid'],
        ])->build();

        return new CompactSerializer()
            ->serialize($jws, 0);
    }
}
