<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Discovery;

use function array_column;
use Heidi\Core\Bridge\InMemory\InMemorySigningKeyRepository;
use Heidi\Core\Bridge\Key\SealedKeyProvider;
use Heidi\Core\Domain\Key\SignatureAlgorithm;
use Heidi\Core\Domain\Key\SigningKey;
use Heidi\Core\Domain\Tenant\Tenant;
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
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class JwksHandlerTest extends TestCase
{
    /**
     * RFC 7517 §5, architecture §4.8: the active key and the retiring one are served, a retired one and
     * another tenant's are not, in creation order; a token the tenant signs verifies against the served
     * document read the way Symfony's OidcJwks reads it (JSON, "keys" filtered on a string "kty", a
     * string "kid" and "use" equal to "sig").
     */
    #[Test]
    public function itServesTheKeysThatVerifyTheTokensOfTheTenant(): void
    {
        $jwts = new Jwts(Fixtures::tenant());
        $repository = new InMemorySigningKeyRepository();
        $repository->save($jwts->key);
        $retiring = new SigningKey(Keys::otherPair()->kid, $jwts->tenant, SignatureAlgorithm::RS256, Keys::otherPair()->publicJwk, 'sealed', Fixtures::now()->modify('-1 day'));
        $retiring->startRetiring(Fixtures::now());
        $repository->save($retiring);
        $retired = self::retiredKey($jwts->tenant);
        $repository->save($retired);
        $repository->save(new SigningKey(Keys::pair()->kid, Fixtures::tenant('globex', 'https://id.globex.example'), SignatureAlgorithm::RS256, Keys::pair()->publicJwk, 'sealed', Fixtures::now()));
        $handler = new JwksHandler(new SealedKeyProvider($repository, Keys::sealer()));

        $response = $handler->handle($jwts->tenant);

        $keys = self::keysAsOidcJwksReadsThem($response->toJson());
        static::assertSame([$jwts->key->kid, $retiring->kid], array_column($keys, 'kid'));
        static::assertSame([$jwts->key->publicJwk, $retiring->publicJwk], $keys);
        static::assertSame([
            'Cache-Control' => 'public, max-age=300',
        ], $response->headers);

        $token = new JwtAccessTokenIssuer($jwts->signer, new PublicSubjectIdentifierResolver())
            ->issue(GrantedAuthorization::fromAuthorizationCode(Tokens::code('the-code', Clients::public($jwts->tenant), Fixtures::session(Fixtures::user($jwts->tenant)), Fixtures::now())), Fixtures::now());
        $jws = new CompactSerializer()
            ->unserialize($token->value);
        static::assertTrue(new JWSVerifier(new AlgorithmManager([new RS256()]))->verifyWithKeySet($jws, JWKSet::createFromKeyData([
            'keys' => $keys,
        ]), 0));
    }

    /**
     * A tenant without any published key gets an empty set, served but not cached.
     */
    #[Test]
    public function aTenantWithoutKeysGetsAnEmptyUncachedSet(): void
    {
        $tenant = Fixtures::tenant();
        $repository = new InMemorySigningKeyRepository();
        $repository->save(self::retiredKey($tenant));

        $response = new JwksHandler(new SealedKeyProvider($repository, Keys::sealer()))->handle($tenant);

        static::assertSame('{"keys":[]}', $response->toJson());
        static::assertSame([
            'Cache-Control' => 'no-store',
        ], $response->headers);
    }

    /**
     * The cache lifetime is the deployment's, five minutes by default, zero meaning "revalidate every
     * time"; a negative one is refused at construction, not on the first request.
     */
    #[Test]
    public function theLifetimeIsAnOptionCheckedAtConstruction(): void
    {
        $jwts = new Jwts(Fixtures::tenant());

        static::assertSame([
            'Cache-Control' => 'public, max-age=60',
        ], new JwksHandler($jwts->keys, 60)
            ->handle($jwts->tenant)
            ->headers);
        static::assertSame([
            'Cache-Control' => 'public, max-age=0',
        ], new JwksHandler($jwts->keys, 0)
            ->handle($jwts->tenant)
            ->headers);

        try {
            new JwksHandler($jwts->keys, -1);
            static::fail('A negative lifetime is refused.');
        } catch (InvalidArgumentException $e) {
            static::assertStringContainsString('number of seconds', $e->getMessage());
        }
    }

    private static function retiredKey(Tenant $tenant): SigningKey
    {
        $retired = new SigningKey(Keys::otherPair()->kid . '-old', $tenant, SignatureAlgorithm::RS256, [
            ...Keys::otherPair()->publicJwk,
            'kid' => Keys::otherPair()->kid . '-old',
        ], 'sealed', Fixtures::now()->modify('-2 days'));
        $retired->startRetiring(Fixtures::now()->modify('-1 day'));
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
        static::assertTrue(is_array($document));
        static::assertTrue(is_array($document['keys'] ?? null));

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
