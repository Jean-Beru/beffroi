<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\JwtLibrary;

use function base64_decode;
use function explode;
use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryJwsSigner;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryJwsVerifier;
use Beffroi\Core\Bridge\Key\OpenedKeys;
use Beffroi\Core\Bridge\Key\SealedKeyProvider;
use Beffroi\Core\Domain\Encoding\Base64Url;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidJwsException;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use function json_decode;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strtr;

final class JwtLibraryTest extends TestCase
{
    private Tenant $tenant;

    private InMemoryTenantKeyRepository $repository;

    private OpenedKeys $opened;

    private SealedKeyProvider $provider;

    private TenantKey $active;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->repository = new InMemoryTenantKeyRepository();
        $this->active = new TenantKey(
            Keys::pair()->kid,
            $this->tenant,
            Algorithms::rs256(),
            Keys::pair()->publicJwk,
            Keys::sealer()->seal($this->tenant, Keys::pair()->privateJwk),
            Fixtures::now(),
            Fixtures::now(),
        );
        $this->active->activate(Fixtures::now());
        $this->repository->save($this->active);
        $this->opened = Keys::opened();
        $this->provider = new SealedKeyProvider($this->repository, $this->opened);
    }

    /**
     * RFC 7638 §3
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
     * RFC 7517 §4
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
     * RFC 7515 §7.1
     */
    #[Test]
    public function itSignsWithTheActiveKeyAndNamesItInTheHeader(): void
    {
        // Given
        $signer = new JwtLibraryJwsSigner($this->provider, Algorithms::all());

        // When
        $jws = $signer->sign($this->tenant, Algorithms::rs256(), '{"sub":"alice"}', [
            'typ' => 'at+jwt',
        ]);

        // Then
        [$header] = explode('.', $jws);
        static::assertSame(
            [
                'typ' => 'at+jwt',
                'alg' => 'RS256',
                'kid' => $this->active->kid,
            ],
            json_decode((string) base64_decode(strtr($header, '-_', '+/'), true), true),
        );
    }

    /**
     * RFC 7515 §7.1
     */
    #[Test]
    public function aKeyOpenedBeforeSignsWithoutBeingLookedUpAgain(): void
    {
        // Given
        $opened = new JwtLibraryJwsSigner($this->provider, Algorithms::all())->open($this->tenant, Algorithms::rs256());
        $this->active->startRetiring(Fixtures::now(), Fixtures::now()->modify('+10 minutes'));

        // When
        $jws = $opened->sign('{"sub":"alice"}', [
            'typ' => 'at+jwt',
        ]);

        // Then
        [$header] = explode('.', $jws);
        static::assertSame(
            [
                'typ' => 'at+jwt',
                'alg' => 'RS256',
                'kid' => $this->active->kid,
            ],
            json_decode((string) base64_decode(strtr($header, '-_', '+/'), true), true),
        );
    }

    #[Test]
    public function theSignatureVerifiesAgainstThePublishedJwks(): void
    {
        // Given
        $jws = new JwtLibraryJwsSigner($this->provider, Algorithms::all())->sign($this->tenant, Algorithms::rs256(), '{"sub":"alice"}');
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
        $jws = new JwtLibraryJwsSigner($this->provider, Algorithms::all())->sign($this->tenant, Algorithms::rs256(), '{"sub":"alice"}', [
            'typ' => 'at+jwt',
        ]);

        // When
        $verified = new JwtLibraryJwsVerifier($this->provider, Algorithms::all())->verify($this->tenant, $jws);

        // Then
        static::assertSame('{"sub":"alice"}', $verified->payload);
        static::assertSame($this->active, $verified->key);
        static::assertSame('at+jwt', $verified->protectedHeader['typ']);
    }

    #[Test]
    public function theCallerCannotOverrideAlgOrKid(): void
    {
        // Given
        $signer = new JwtLibraryJwsSigner($this->provider, Algorithms::all());

        // When
        $jws = $signer->sign($this->tenant, Algorithms::rs256(), 'x', [
            'alg' => 'none',
            'kid' => 'forged',
        ]);

        // Then
        static::assertSame($this->active, new JwtLibraryJwsVerifier($this->provider, Algorithms::all())->verify($this->tenant, $jws)->key);
    }

    #[Test]
    public function signingWithoutAnActiveKeyFails(): void
    {
        // Given
        $signer = new JwtLibraryJwsSigner(new SealedKeyProvider(new InMemoryTenantKeyRepository(), Keys::opened()), Algorithms::all());

        // Then
        $this->expectException(KeyNotFoundException::class);

        // When
        $signer->sign($this->tenant, Algorithms::rs256(), 'x');
    }

    /**
     * OIDC Core §10.1.1
     */
    #[Test]
    public function aRetiringKeyStillVerifies(): void
    {
        // Given
        $this->active->startRetiring(Fixtures::now(), Fixtures::now()->modify('+10 minutes'));
        $jws = self::signWith(Keys::pair()->privateJwk, 'payload');

        // When
        $verified = new JwtLibraryJwsVerifier($this->provider, Algorithms::all())->verify($this->tenant, $jws);

        // Then
        static::assertSame($this->active, $verified->key);
    }

    #[Test]
    public function aRetiringKeyNoLongerSigns(): void
    {
        // Given
        $this->active->startRetiring(Fixtures::now(), Fixtures::now()->modify('+10 minutes'));
        $signer = new JwtLibraryJwsSigner($this->provider, Algorithms::all());

        // Then
        $this->expectException(KeyNotFoundException::class);

        // When
        $signer->sign($this->tenant, Algorithms::rs256(), 'x');
    }

    #[Test]
    public function aStagedKeyDoesNotSign(): void
    {
        // Given
        $repository = new InMemoryTenantKeyRepository();
        $repository->save(
            new TenantKey(
                Keys::pair()->kid,
                $this->tenant,
                Algorithms::rs256(),
                Keys::pair()->publicJwk,
                Keys::sealer()->seal($this->tenant, Keys::pair()->privateJwk),
                Fixtures::now(),
                Fixtures::now(),
            ),
        );
        $signer = new JwtLibraryJwsSigner(new SealedKeyProvider($repository, Keys::opened()), Algorithms::all());

        // Then
        $this->expectException(KeyNotFoundException::class);

        // When
        $signer->sign($this->tenant, Algorithms::rs256(), 'x');
    }

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
        new JwtLibraryJwsVerifier($this->provider, Algorithms::all())->verify($this->tenant, $jws);
    }

    /**
     * RFC 8725 §3.1, §3.2
     */
    #[Test]
    public function itRefusesTokensSignedWithAnotherAlgorithm(): void
    {
        // Given
        $hmac = new JWSBuilder(new AlgorithmManager([new HS256()]))
            ->create()
            ->withPayload('payload')
            ->addSignature(
                new JWK([
                    'kty' => 'oct',
                    'k' => rtrim(strtr(base64_encode(str_repeat('k', 32)), '+/', '-_'), '='),
                ]),
                [
                    'alg' => 'HS256',
                    'kid' => $this->active->kid,
                ],
            )
            ->build();
        $jws = new CompactSerializer()->serialize($hmac, 0);

        // Then
        $this->expectException(InvalidJwsException::class);

        // When
        new JwtLibraryJwsVerifier($this->provider, Algorithms::all())->verify($this->tenant, $jws);
    }

    #[Test]
    public function itRefusesAKeyTheTenantDoesNotPublish(): void
    {
        // Given
        $jws = self::signWith(Keys::otherPair()->privateJwk, 'payload');

        // Then
        $this->expectException(InvalidJwsException::class);

        // When
        new JwtLibraryJwsVerifier($this->provider, Algorithms::all())->verify($this->tenant, $jws);
    }

    #[Test]
    public function itRefusesAKeyOfAnotherTenant(): void
    {
        // Given
        $jws = self::signWith(Keys::pair()->privateJwk, 'payload');

        // Then
        $this->expectException(InvalidJwsException::class);

        // When
        new JwtLibraryJwsVerifier($this->provider, Algorithms::all())->verify(Fixtures::tenant('other', 'https://id.other.example'), $jws);
    }

    #[Test]
    public function itRefusesATokenWithoutKid(): void
    {
        // Given
        $built = new JWSBuilder(new AlgorithmManager([new RS256()]))
            ->create()
            ->withPayload('payload')
            ->addSignature(new JWK(Keys::pair()->privateJwk), [
                'alg' => 'RS256',
            ])
            ->build();
        $jws = new CompactSerializer()->serialize($built, 0);

        // Then
        $this->expectException(InvalidJwsException::class);

        // When
        new JwtLibraryJwsVerifier($this->provider, Algorithms::all())->verify($this->tenant, $jws);
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
        new JwtLibraryJwsVerifier($this->provider, Algorithms::all())->verify($this->tenant, $forged);
    }

    #[Test]
    public function itRefusesWhatIsNotACompactJws(): void
    {
        // Then
        $this->expectException(InvalidJwsException::class);

        // When
        new JwtLibraryJwsVerifier($this->provider, Algorithms::all())->verify($this->tenant, 'not.a.jws.at.all');
    }

    /**
     * RFC 7515 §4.1.11
     */
    #[Test]
    public function itRefusesATokenThatMarksAParameterCritical(): void
    {
        // Given
        $jws = new JwtLibraryJwsSigner($this->provider, Algorithms::all())->sign($this->tenant, Algorithms::rs256(), '{"sub":"alice"}', [
            'crit' => ['urn:example:must-understand'],
            'urn:example:must-understand' => true,
        ]);

        // Then
        $this->expectException(InvalidJwsException::class);
        $this->expectExceptionMessageIs('The token uses an extension of JOSE this provider does not understand (RFC 7515 section 4.1.11).');

        // When
        new JwtLibraryJwsVerifier($this->provider, Algorithms::all())->verify($this->tenant, $jws);
    }

    /**
     * RFC 7797 §6
     */
    #[Test]
    public function itRefusesATokenWhosePayloadIsNotEncoded(): void
    {
        // Given
        $header = Base64Url::encode(json_encode([
            'alg' => 'RS256',
            'kid' => $this->active->kid,
            'b64' => false,
        ], JSON_THROW_ON_ERROR));
        $payload = '{"sub":"alice"}';
        $signature = new RS256()->sign(new JWK(Keys::pair()->privateJwk), $header . '.' . $payload);

        // Then
        $this->expectException(InvalidJwsException::class);
        $this->expectExceptionMessageIs('The token uses an extension of JOSE this provider does not understand (RFC 7515 section 4.1.11).');

        // When
        new JwtLibraryJwsVerifier($this->provider, Algorithms::all())->verify($this->tenant, $header . '.' . $payload . '.' . Base64Url::encode($signature));
    }

    /**
     * RFC 7515 §7.1
     */
    #[Test]
    public function itRefusesATokenWithoutPayload(): void
    {
        // Given
        $header = Base64Url::encode(json_encode([
            'alg' => 'RS256',
            'kid' => $this->active->kid,
        ], JSON_THROW_ON_ERROR));

        // Then
        $this->expectException(InvalidJwsException::class);
        $this->expectExceptionMessageIs('The signature of the token cannot be checked.');

        // When
        new JwtLibraryJwsVerifier($this->provider, Algorithms::all())->verify($this->tenant, $header . '..' . Base64Url::encode('signature'));
    }

    #[Test]
    public function theProviderOpensTheActiveKey(): void
    {
        // When
        $key = $this->provider->activeKey($this->tenant, Algorithms::rs256());

        // Then
        static::assertSame(Keys::pair()->privateJwk, $key->privateJwk);
    }

    #[Test]
    public function theProviderOpensAKeyOnce(): void
    {
        // Given
        $first = $this->provider->activeKey($this->tenant, Algorithms::rs256());

        // When
        $second = $this->provider->activeKey($this->tenant, Algorithms::rs256());

        // Then
        static::assertSame($first, $second);
    }

    #[Test]
    public function theProviderForgetsAKeyOnceItIsNoLongerActive(): void
    {
        // Given
        $previous = $this->provider->activeKey($this->tenant, Algorithms::rs256());
        $this->active->startRetiring(Fixtures::now(), Fixtures::now()->modify('+10 minutes'));
        $next = new TenantKey(
            Keys::otherPair()->kid,
            $this->tenant,
            Algorithms::rs256(),
            Keys::otherPair()->publicJwk,
            Keys::sealer()->seal($this->tenant, Keys::otherPair()->privateJwk),
            Fixtures::now(),
            Fixtures::now(),
        );
        $next->activate(Fixtures::now());
        $this->repository->save($next);

        // When
        $opened = $this->provider->activeKey($this->tenant, Algorithms::rs256());

        // Then
        static::assertSame($next, $opened->key);
        static::assertNotSame($previous, $this->opened->open($this->tenant, $this->active));
    }

    #[Test]
    public function theProviderPublishesStagedActiveAndRetiringKeys(): void
    {
        // Given
        $retiring = new TenantKey(
            Keys::otherPair()->kid,
            $this->tenant,
            Algorithms::rs256(),
            Keys::otherPair()->publicJwk,
            Keys::sealer()->seal($this->tenant, Keys::otherPair()->privateJwk),
            Fixtures::now()->modify('-1 day'),
            Fixtures::now()->modify('-1 day'),
        );
        $retiring->activate(Fixtures::now()->modify('-1 day'));
        $retiring->startRetiring(Fixtures::now(), Fixtures::now()->modify('+10 minutes'));
        $this->repository->save($retiring);
        $staged = new TenantKey(
            'staged-kid',
            $this->tenant,
            Algorithms::rs256(),
            [
                ...Keys::otherPair()->publicJwk,
                'kid' => 'staged-kid',
            ],
            'sealed',
            Fixtures::now()->modify('+1 minute'),
            Fixtures::now()->modify('+7 minutes'),
        );
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
        $jws = new JWSBuilder(new AlgorithmManager([new RS256()]))
            ->create()
            ->withPayload($payload)
            ->addSignature(new JWK($privateJwk), [
                'alg' => 'RS256',
                'kid' => $privateJwk['kid'],
            ])
            ->build();

        return new CompactSerializer()->serialize($jws, 0);
    }
}
