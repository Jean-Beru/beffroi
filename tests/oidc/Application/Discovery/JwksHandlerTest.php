<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Discovery;

use function array_column;
use function array_map;
use Heidi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Heidi\Core\Bridge\Key\SealedKeyProvider;
use Heidi\Core\Domain\Key\TenantKey;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\Keys;
use Heidi\Oidc\Application\Claims\PublicSubjectIdentifierResolver;
use Heidi\Oidc\Application\Discovery\JwksHandler;
use Heidi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Jwts;
use Heidi\Oidc\Tests\Fixture\Tokens;
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
        $this->retiring = new TenantKey(Keys::otherPair()->kid, $this->jwts->tenant, Algorithms::rs256(), Keys::otherPair()->publicJwk, 'sealed', Fixtures::now()->modify('-1 day'), Fixtures::now()->modify('-1 day'));
        $this->retiring->activate(Fixtures::now()->modify('-1 day'));
        $this->retiring->startRetiring(Fixtures::now(), Fixtures::now()->modify('+10 minutes'));
        $repository->save($this->retiring);
        $repository->save(self::retiredKey($this->jwts->tenant));
        $globex = new TenantKey(Keys::pair()->kid, Fixtures::tenant('globex', 'https://id.globex.example'), Algorithms::rs256(), Keys::pair()->publicJwk, 'sealed', Fixtures::now(), Fixtures::now());
        $globex->activate(Fixtures::now());
        $repository->save($globex);
        $this->handler = new JwksHandler(new SealedKeyProvider($repository, Keys::sealer()));
    }

    /**
     * RFC 7517 §5, architecture §4.8: the active key and the retiring one are served, a retired one and
     * another tenant's are not, in creation order, read the way Symfony's OidcJwks reads a document
     * (JSON, "keys" filtered on a string "kty", a string "kid" and "use" equal to "sig").
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
     * RFC 7517 §5 and RFC 7515 §4.1.4: a tenant that signs with two algorithms publishes one key per
     * algorithm, each naming itself, so that a relying party picks by "kid" and knows what to verify with.
     * The two keys of the fixture are created at the same instant, and the set orders same-instant keys by
     * "kid", which is a thumbprint: which of them comes first is not a behaviour, so it is not asserted.
     */
    #[Test]
    public function theSetCarriesOneKeyPerAlgorithmTheTenantSignsWith(): void
    {
        // Given
        $es256 = $this->jwts->activate(Algorithms::es256());

        // When
        $keys = self::keysAsOidcJwksReadsThem(new JwksHandler($this->jwts->keys)->handle($this->jwts->tenant)->toJson());

        // Then
        static::assertEqualsCanonicalizing([
            [$this->jwts->key->kid, 'RS256', 'RSA'],
            [$es256->kid, 'ES256', 'EC'],
        ], array_map(static fn (array $jwk): array => [$jwk['kid'], $jwk['alg'], $jwk['kty']], $keys));
    }

    #[Test]
    public function theSetIsCachedForFiveMinutesByDefault(): void
    {
        // When
        $response = $this->handler->handle($this->jwts->tenant);

        // Then
        static::assertSame([
            'Cache-Control' => 'public, max-age=300',
        ], $response->headers);
    }

    /**
     * A token the tenant signs verifies against the served document.
     */
    #[Test]
    public function aTokenOfTheTenantVerifiesAgainstTheServedKeys(): void
    {
        // Given
        $token = new JwtAccessTokenIssuer($this->jwts->signer, new PublicSubjectIdentifierResolver(), Algorithms::all())
            ->issue(GrantedAuthorization::fromAuthorizationCode(Tokens::code('the-code', Clients::public($this->jwts->tenant), Fixtures::session(Fixtures::user($this->jwts->tenant)), Fixtures::now())), Fixtures::now());
        $keys = JWKSet::createFromKeyData([
            'keys' => self::keysAsOidcJwksReadsThem($this->handler->handle($this->jwts->tenant)->toJson()),
        ]);

        // When
        $verified = new JWSVerifier(new AlgorithmManager([new RS256()]))->verifyWithKeySet(new CompactSerializer()->unserialize($token->value), $keys, 0);

        // Then
        static::assertTrue($verified);
    }

    /**
     * A tenant without any published key gets an empty set, served but not cached.
     */
    #[Test]
    public function aTenantWithoutKeysGetsAnEmptyUncachedSet(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $repository = new InMemoryTenantKeyRepository();
        $repository->save(self::retiredKey($tenant));
        $handler = new JwksHandler(new SealedKeyProvider($repository, Keys::sealer()));

        // When
        $response = $handler->handle($tenant);

        // Then
        static::assertSame('{"keys":[]}', $response->toJson());
        static::assertSame([
            'Cache-Control' => 'no-store',
        ], $response->headers);
    }

    /**
     * The cache lifetime is the deployment's, zero meaning "revalidate every time".
     */
    #[Test]
    #[DataProvider('provideLifetimes')]
    public function theLifetimeIsAnOption(int $lifetime, string $cacheControl): void
    {
        // Given
        $handler = new JwksHandler($this->jwts->keys, $lifetime);

        // When
        $response = $handler->handle($this->jwts->tenant);

        // Then
        static::assertSame([
            'Cache-Control' => $cacheControl,
        ], $response->headers);
    }

    /**
     * @return iterable<string, array{int, string}>
     */
    public static function provideLifetimes(): iterable
    {
        yield 'one minute' => [60, 'public, max-age=60'];
        yield 'zero' => [0, 'public, max-age=0'];
    }

    /**
     * A negative lifetime is refused at construction, not on the first request.
     */
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
        $retired = new TenantKey(Keys::otherPair()->kid . '-old', $tenant, Algorithms::rs256(), [
            ...Keys::otherPair()->publicJwk,
            'kid' => Keys::otherPair()->kid . '-old',
        ], 'sealed', Fixtures::now()->modify('-2 days'), Fixtures::now()->modify('-2 days'));
        $retired->activate(Fixtures::now()->modify('-2 days'));
        $retired->startRetiring(Fixtures::now()->modify('-1 day'), Fixtures::now());
        $retired->retire(Fixtures::now());

        return $retired;
    }

    /**
     * What Symfony's OidcJwks::fromResponse() keeps of a JWKS payload, with its default strict key usage.
     *
     * @return list<array<string, mixed>>
     */
    private static function keysAsOidcJwksReadsThem(string $payload): array
    {
        $document = json_decode($payload, true, 512, JSON_THROW_ON_ERROR);
        static::assertIsArray($document);
        static::assertIsArray($document['keys'] ?? null);

        $keys = [];
        foreach ($document['keys'] as $jwk) {
            if (! is_array($jwk) || ! is_string($jwk['kty'] ?? null) || $jwk['kty'] === '' || ! is_string($jwk['kid'] ?? null) || ($jwk['use'] ?? null) !== 'sig') {
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
