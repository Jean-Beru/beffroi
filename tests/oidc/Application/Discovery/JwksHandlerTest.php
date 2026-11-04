<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Discovery;

use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Oidc\Tests\Fixture\Grants;
use function array_column;
use function array_map;
use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Bridge\Key\SealedKeyProvider;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use Beffroi\Oidc\Application\Discovery\JwksHandler;
use Beffroi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Beffroi\Oidc\Domain\Token\UserAuthorization;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Jwts;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use function is_array;
use function is_string;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Beffroi\Oidc\Tests\Fixture\Subjects;
use PHPUnit\Framework\TestCase;

final class JwksHandlerTest extends TestCase
{
    private Jwts $jwts;

    private TenantKey $retiring;

    private JwksHandler $handler;

    protected function setUp(): void
    {
        $this->jwts = new Jwts(Fixtures::tenant());
        $repository = new InMemoryTenantKeyRepository();
        $repository->save($this->jwts->key);
        $this->retiring = new TenantKey(
            Keys::otherPair()->kid,
            $this->jwts->tenant,
            Algorithms::rs256(),
            Keys::otherPair()->publicJwk,
            'sealed',
            Fixtures::now()->modify('-1 day'),
            Fixtures::now()->modify('-1 day'),
        );
        $this->retiring->activate(Fixtures::now()->modify('-1 day'));
        $this->retiring->startRetiring(Fixtures::now(), Fixtures::now()->modify('+10 minutes'));
        $repository->save($this->retiring);
        $repository->save(self::retiredKey($this->jwts->tenant));
        $globex = new TenantKey(
            Keys::pair()->kid,
            Fixtures::tenant('globex', 'https://id.globex.example'),
            Algorithms::rs256(),
            Keys::pair()->publicJwk,
            'sealed',
            Fixtures::now(),
            Fixtures::now(),
        );
        $globex->activate(Fixtures::now());
        $repository->save($globex);
        $this->handler = new JwksHandler(new SealedKeyProvider($repository, Keys::opened()));
    }

    /**
     * RFC 7517 §5, Architecture §4.8
     */
    #[Test]
    public function itServesTheActiveAndRetiringKeysOfTheTenant(): void
    {
        // When
        $response = $this->handler->handle($this->jwts->tenant);

        // Then
        $keys = self::keysAsOidcJwksReadsThem($response->toJson());
        static::assertSame([$this->retiring->kid, $this->jwts->key->kid], array_column($keys, 'kid'));
        static::assertSame([$this->retiring->publicJwk, $this->jwts->key->publicJwk], $keys);
    }

    /**
     * RFC 7517 §5, RFC 7515 §4.1.4
     */
    #[Test]
    public function theSetCarriesOneKeyPerAlgorithmTheTenantSignsWith(): void
    {
        // Given
        $es256 = $this->jwts->activate(Algorithms::es256());

        // When
        $keys = self::keysAsOidcJwksReadsThem(
            new JwksHandler($this->jwts->keys)
                ->handle($this->jwts->tenant)
                ->toJson(),
        );

        // Then
        static::assertEqualsCanonicalizing(
            [
                [$this->jwts->key->kid, 'RS256', 'RSA'],
                [$es256->kid, 'ES256', 'EC'],
            ],
            array_map(static fn (array $jwk): array => [$jwk['kid'], $jwk['alg'], $jwk['kty']], $keys),
        );
    }

    #[Test]
    public function theSetIsCachedForFiveMinutesByDefault(): void
    {
        // When
        $response = $this->handler->handle($this->jwts->tenant);

        // Then
        static::assertSame(
            [
                'Cache-Control' => 'public, max-age=300',
            ],
            $response->headers,
        );
    }

    #[Test]
    public function aTokenOfTheTenantVerifiesAgainstTheServedKeys(): void
    {
        // Given
        $token = Tokens::accessToken(
            new JwtAccessTokenIssuer(
                $this->jwts->signer,
                Subjects::publicKind(),
                Algorithms::all(),
                new SymfonyUuidGenerator(),
                Subjects::sealedPerson(),
            ),
            UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
                'the-code',
                Clients::public($this->jwts->tenant),
                Fixtures::session(Fixtures::user($this->jwts->tenant)),
                Fixtures::now(),
            )),
            Fixtures::now(),
        );
        $keys = JWKSet::createFromKeyData([
            'keys' => self::keysAsOidcJwksReadsThem($this->handler->handle($this->jwts->tenant)->toJson()),
        ]);

        // When
        $verified = new JWSVerifier(new AlgorithmManager([new RS256()]))->verifyWithKeySet(new CompactSerializer()->unserialize($token->value), $keys, 0);

        // Then
        static::assertTrue($verified);
    }

    #[Test]
    public function aTenantWithoutKeysGetsAnEmptyUncachedSet(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $repository = new InMemoryTenantKeyRepository();
        $repository->save(self::retiredKey($tenant));
        $handler = new JwksHandler(new SealedKeyProvider($repository, Keys::opened()));

        // When
        $response = $handler->handle($tenant);

        // Then
        static::assertSame('{"keys":[]}', $response->toJson());
        static::assertSame(
            [
                'Cache-Control' => 'no-store',
            ],
            $response->headers,
        );
    }

    #[Test]
    #[DataProvider('provideLifetimes')]
    public function theLifetimeIsAnOption(int $lifetime, string $cacheControl): void
    {
        // Given
        $handler = new JwksHandler($this->jwts->keys, $lifetime);

        // When
        $response = $handler->handle($this->jwts->tenant);

        // Then
        static::assertSame(
            [
                'Cache-Control' => $cacheControl,
            ],
            $response->headers,
        );
    }

    /**
     * @return iterable<string, array{int, string}>
     */
    public static function provideLifetimes(): iterable
    {
        yield 'one minute' => [60, 'public, max-age=60'];
        yield 'zero' => [0, 'public, max-age=0'];
    }

    #[Test]
    public function aNegativeLifetimeIsRefusedAtConstruction(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('number of seconds');

        // When
        new JwksHandler($this->jwts->keys, -1);
    }

    private static function retiredKey(Tenant $tenant): TenantKey
    {
        $retired = new TenantKey(
            Keys::otherPair()->kid . '-old',
            $tenant,
            Algorithms::rs256(),
            [
                ...Keys::otherPair()->publicJwk,
                'kid' => Keys::otherPair()->kid . '-old',
            ],
            'sealed',
            Fixtures::now()->modify('-2 days'),
            Fixtures::now()->modify('-2 days'),
        );
        $retired->activate(Fixtures::now()->modify('-2 days'));
        $retired->startRetiring(Fixtures::now()->modify('-1 day'), Fixtures::now());
        $retired->retire(Fixtures::now());

        return $retired;
    }

    /**
     * @return list<array<string, mixed>>
     */
    private static function keysAsOidcJwksReadsThem(string $payload): array
    {
        $document = json_decode($payload, true, 512, JSON_THROW_ON_ERROR);
        static::assertIsArray($document);
        static::assertIsArray($document['keys'] ?? null);

        $keys = [];
        foreach ($document['keys'] as $jwk) {
            if (
                ! is_array($jwk)
                || ! is_string($jwk['kty'] ?? null)
                || $jwk['kty'] === ''
                || ! is_string($jwk['kid'] ?? null)
                || ($jwk['use'] ?? null) !== 'sig'
            ) {
                continue;
            }
            $members = [];
            foreach ($jwk as $member => $value) {
                static::assertIsString($member);
                $members[$member] = $value;
            }
            $keys[] = $members;
        }

        return $keys;
    }
}
