<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Bridge\JwtFramework;

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
        $this->active = new SigningKey(Keys::pair()->kid, $this->tenant, SignatureAlgorithm::RS256, Keys::pair()->publicJwk, Keys::sealer()->seal(Keys::pair()->privateJwk), Fixtures::now());
        $this->repository->save($this->active);
        $this->provider = new SealedKeyProvider($this->repository, Keys::sealer());
    }

    /**
     * RFC 7638 §3: the kid is the SHA-256 thumbprint; RFC 7517 §4: the public JWK carries kid, alg and use;
     * RFC 7518 §3.3: at least 2048 bits.
     */
    #[Test]
    public function theGeneratorProducesAThumbprintKidAndAPublicJwkWithoutPrivateMembers(): void
    {
        $pair = Keys::pair();

        static::assertSame($pair->kid, new JWK($pair->publicJwk)->thumbprint('sha256'));
        static::assertSame('RSA', $pair->publicJwk['kty']);
        static::assertSame('RS256', $pair->publicJwk['alg']);
        static::assertSame('sig', $pair->publicJwk['use']);
        static::assertSame($pair->kid, $pair->publicJwk['kid']);
        static::assertArrayNotHasKey('d', $pair->publicJwk);
        static::assertArrayHasKey('d', $pair->privateJwk);
        static::assertSame($pair->kid, $pair->privateJwk['kid']);
        static::assertNotSame($pair->kid, Keys::otherPair()->kid);
    }

    #[Test]
    public function theGeneratorRefusesKeysUnderTheMinimum(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new JwtFrameworkKeyPairGenerator(1024);
    }

    /**
     * RFC 7515 §7.1 compact serialization, header with alg and kid; verified by jwt-framework against the
     * published JWK Set, the way a relying party would.
     */
    #[Test]
    public function itSignsWithTheActiveKeyAndTheResultVerifiesAgainstThePublishedJwks(): void
    {
        $signer = new JwtFrameworkJwsSigner($this->provider);

        $jws = $signer->sign($this->tenant, SignatureAlgorithm::RS256, '{"sub":"alice"}', [
            'typ' => 'at+jwt',
        ]);

        [$header] = explode('.', $jws);
        $decoded = json_decode((string) base64_decode(strtr($header, '-_', '+/'), true), true);
        static::assertSame([
            'typ' => 'at+jwt',
            'alg' => 'RS256',
            'kid' => $this->active->kid,
        ], $decoded);

        $jwks = JWKSet::createFromKeyData($this->provider->publicKeys($this->tenant)->toJwks());
        $parsed = new CompactSerializer()
            ->unserialize($jws);
        static::assertTrue(new JWSVerifier(new AlgorithmManager([new RS256()]))->verifyWithKeySet($parsed, $jwks, 0));

        $verified = new JwtFrameworkJwsVerifier($this->provider)
            ->verify($this->tenant, $jws);
        static::assertSame('{"sub":"alice"}', $verified->payload);
        static::assertSame($this->active, $verified->key);
        static::assertSame('at+jwt', $verified->protectedHeader['typ']);
    }

    #[Test]
    public function theCallerCannotOverrideAlgOrKid(): void
    {
        $jws = new JwtFrameworkJwsSigner($this->provider)
            ->sign($this->tenant, SignatureAlgorithm::RS256, 'x', [
                'alg' => 'none',
                'kid' => 'forged',
            ]);

        static::assertSame($this->active, new JwtFrameworkJwsVerifier($this->provider)->verify($this->tenant, $jws)->key);
    }

    #[Test]
    public function signingWithoutAnActiveKeyFails(): void
    {
        $signer = new JwtFrameworkJwsSigner(new SealedKeyProvider(new InMemorySigningKeyRepository(), Keys::sealer()));

        $this->expectException(KeyNotFoundException::class);
        $signer->sign($this->tenant, SignatureAlgorithm::RS256, 'x');
    }

    #[Test]
    public function aRetiringKeyStillVerifiesButNoLongerSigns(): void
    {
        $this->active->startRetiring(Fixtures::now());
        $jws = self::signWith(Keys::pair()->privateJwk, 'payload');

        static::assertSame($this->active, new JwtFrameworkJwsVerifier($this->provider)->verify($this->tenant, $jws)->key);

        $this->expectException(KeyNotFoundException::class);
        new JwtFrameworkJwsSigner($this->provider)
            ->sign($this->tenant, SignatureAlgorithm::RS256, 'x');
    }

    #[Test]
    public function aRetiredKeyNoLongerVerifies(): void
    {
        $this->active->startRetiring(Fixtures::now());
        $this->active->retire(Fixtures::now());

        $this->expectException(InvalidJwsException::class);
        new JwtFrameworkJwsVerifier($this->provider)
            ->verify($this->tenant, self::signWith(Keys::pair()->privateJwk, 'payload'));
    }

    /**
     * RFC 8725 §3.1 and §3.2: the algorithm comes from the verifier, never from the token; "none" and HMAC
     * are refused whatever the header says.
     */
    #[Test]
    public function itRefusesTokensSignedWithAnotherAlgorithm(): void
    {
        $hmac = new JWSBuilder(new AlgorithmManager([new HS256()]))->create()->withPayload('payload')->addSignature(new JWK([
            'kty' => 'oct',
            'k' => rtrim(strtr(base64_encode(str_repeat('k', 32)), '+/', '-_'), '='),
        ]), [
            'alg' => 'HS256',
            'kid' => $this->active->kid,
        ])->build();

        $this->expectException(InvalidJwsException::class);
        new JwtFrameworkJwsVerifier($this->provider)
            ->verify($this->tenant, new CompactSerializer()->serialize($hmac, 0));
    }

    #[Test]
    public function itRefusesAKeyTheTenantDoesNotPublish(): void
    {
        $this->expectException(InvalidJwsException::class);

        new JwtFrameworkJwsVerifier($this->provider)
            ->verify($this->tenant, self::signWith(Keys::otherPair()->privateJwk, 'payload'));
    }

    #[Test]
    public function itRefusesAKeyOfAnotherTenant(): void
    {
        $this->expectException(InvalidJwsException::class);

        new JwtFrameworkJwsVerifier($this->provider)
            ->verify(Fixtures::tenant('other', 'https://id.other.example'), self::signWith(Keys::pair()->privateJwk, 'payload'));
    }

    #[Test]
    public function itRefusesATokenWithoutKid(): void
    {
        $jws = new JWSBuilder(new AlgorithmManager([new RS256()]))->create()->withPayload('payload')->addSignature(new JWK(Keys::pair()->privateJwk), [
            'alg' => 'RS256',
        ])->build();

        $this->expectException(InvalidJwsException::class);
        new JwtFrameworkJwsVerifier($this->provider)
            ->verify($this->tenant, new CompactSerializer()->serialize($jws, 0));
    }

    #[Test]
    public function itRefusesATamperedPayload(): void
    {
        $jws = self::signWith(Keys::pair()->privateJwk, '{"sub":"alice"}');
        [$header, , $signature] = explode('.', $jws);
        $forged = $header . '.' . rtrim(strtr(base64_encode('{"sub":"mallory"}'), '+/', '-_'), '=') . '.' . $signature;

        $this->expectException(InvalidJwsException::class);
        new JwtFrameworkJwsVerifier($this->provider)
            ->verify($this->tenant, $forged);
    }

    #[Test]
    public function itRefusesWhatIsNotACompactJws(): void
    {
        $this->expectException(InvalidJwsException::class);

        new JwtFrameworkJwsVerifier($this->provider)
            ->verify($this->tenant, 'not.a.jws.at.all');
    }

    #[Test]
    public function theProviderOpensAKeyOnceAndPublishesActiveAndRetiringKeys(): void
    {
        $first = $this->provider->activeKey($this->tenant, SignatureAlgorithm::RS256);
        static::assertSame(Keys::pair()->privateJwk, $first->privateJwk);
        static::assertSame($first, $this->provider->activeKey($this->tenant, SignatureAlgorithm::RS256));

        $other = new SigningKey(Keys::otherPair()->kid, $this->tenant, SignatureAlgorithm::RS256, Keys::otherPair()->publicJwk, Keys::sealer()->seal(Keys::otherPair()->privateJwk), Fixtures::now());
        $other->startRetiring(Fixtures::now());
        $this->repository->save($other);

        static::assertCount(2, $this->provider->publicKeys($this->tenant)->keys);
        static::assertTrue($this->provider->publicKeys(Fixtures::tenant('other', 'https://id.other.example'))->isEmpty());
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
