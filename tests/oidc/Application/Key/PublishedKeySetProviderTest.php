<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Key;

use function array_map;
use DateInterval;
use Beffroi\Oidc\Application\Key\PublishedKeySetProvider;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientJwksCache;
use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
use Beffroi\Oidc\Tests\Fixture\ClientAssertions;
use Beffroi\Oidc\Tests\Fixture\FakeClientJwksFetcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * Where the keys of a party this provider verifies a signature of come from (RFC 7517 §5, RFC 7591 §2):
 * the set it wrote down, or the set read back from the URL it publishes them behind, kept between
 * requests and read again at most once per cooldown when a signature names a "kid" the kept set does not
 * hold. The one reading, whoever publishes: a client, or an issuer a tenant trusts.
 */
final class PublishedKeySetProviderTest extends TestCase
{
    private const string JWKS_URI = 'https://key.example/jwks';

    private const int COOLDOWN = 300;

    private MockClock $clock;

    private InMemoryClientJwksCache $cache;

    protected function setUp(): void
    {
        $this->clock = new MockClock('2026-09-15T10:00:00+00:00');
        $this->cache = new InMemoryClientJwksCache();
    }

    #[Test]
    public function aSetWrittenDownIsNeverFetched(): void
    {
        // Given
        $fetcher = new FakeClientJwksFetcher([ClientAssertions::publishedKeys()]);
        $written = ClientAssertions::publishedKeys();

        // When
        $keys = $this->provider($fetcher)->keysOf($written, ClientAssertions::KEY_ID);

        // Then
        static::assertSame($written, $keys);
        static::assertSame([], $fetcher->fetched);
    }

    #[Test]
    public function aSetBehindAUrlIsReadOnce(): void
    {
        // Given
        $fetcher = new FakeClientJwksFetcher([ClientAssertions::publishedKeys()]);
        $provider = $this->provider($fetcher);
        $provider->keysOf(self::jwksUri(), ClientAssertions::KEY_ID);

        // When
        $provider->keysOf(self::jwksUri(), ClientAssertions::KEY_ID);

        // Then
        static::assertSame([self::JWKS_URI], self::urls($fetcher));
    }

    /**
     * A party that rotates a key is followed: the "kid" it now signs with is not in the kept set, and
     * the set is read again once the cooldown has passed.
     */
    #[Test]
    public function anUnknownKeyIdentifierCostsOneRefetch(): void
    {
        // Given
        $rotated = ClientAssertions::publishedKeys();
        $fetcher = new FakeClientJwksFetcher([self::otherKeys(), $rotated]);
        $provider = $this->provider($fetcher);
        $provider->keysOf(self::jwksUri(), 'old-key');
        $this->clock->modify('+' . (self::COOLDOWN + 1) . ' seconds');

        // When
        $keys = $provider->keysOf(self::jwksUri(), ClientAssertions::KEY_ID);

        // Then
        static::assertSame($rotated->keys, $keys->keys);
        static::assertCount(2, $fetcher->fetched);
    }

    /**
     * A party that signs with a key it never published cannot make the provider call it on every
     * request.
     */
    #[Test]
    public function aSecondUnknownKeyIdentifierInsideTheCooldownCostsNoRefetch(): void
    {
        // Given
        $fetcher = new FakeClientJwksFetcher([self::otherKeys(), self::otherKeys()]);
        $provider = $this->provider($fetcher);
        $provider->keysOf(self::jwksUri(), 'old-key');
        $this->clock->modify('+' . (self::COOLDOWN + 1) . ' seconds');
        $provider->keysOf(self::jwksUri(), ClientAssertions::KEY_ID);

        // When
        $provider->keysOf(self::jwksUri(), ClientAssertions::KEY_ID);

        // Then
        static::assertCount(2, $fetcher->fetched);
    }

    /**
     * A signature that names no key is verified against everything the party published, so there is
     * nothing to read again.
     */
    #[Test]
    public function aSignatureThatNamesNoKeyCostsNoRefetch(): void
    {
        // Given
        $fetcher = new FakeClientJwksFetcher([self::otherKeys()]);
        $provider = $this->provider($fetcher);
        $provider->keysOf(self::jwksUri(), null);
        $this->clock->modify('+1 day');

        // When
        $provider->keysOf(self::jwksUri(), null);

        // Then
        static::assertCount(1, $fetcher->fetched);
    }

    /**
     * A kept set is filed under the URL it was read from: two parties publishing behind the same URL
     * publish the same document and share one read, and whoever registered that URL does not file it.
     */
    #[Test]
    public function aSetIsKeptUnderTheUrlItWasReadFrom(): void
    {
        // Given
        $fetcher = new FakeClientJwksFetcher([ClientAssertions::publishedKeys()]);
        $provider = $this->provider($fetcher);
        $provider->keysOf(new ClientUri(self::JWKS_URI), ClientAssertions::KEY_ID);

        // When
        $provider->keysOf(new ClientUri('https://other.example/jwks'), ClientAssertions::KEY_ID);

        // Then
        static::assertSame([self::JWKS_URI, 'https://other.example/jwks'], self::urls($fetcher));
    }

    /**
     * A URL that cannot be read is raised to whoever was verifying a signature against it, and nothing
     * is kept.
     */
    #[Test]
    public function aUrlThatCannotBeReadIsRaised(): void
    {
        // Given
        $fetcher = new FakeClientJwksFetcher([ClientAssertions::publishedKeys()]);
        $fetcher->failure = new ClientKeysUnavailableException('https://key.example/jwks answered 500.');

        // Then
        $this->expectException(ClientKeysUnavailableException::class);
        $this->expectExceptionMessageIs('https://key.example/jwks answered 500.');

        // When
        $this->provider($fetcher)->keysOf(self::jwksUri(), ClientAssertions::KEY_ID);
    }

    private function provider(FakeClientJwksFetcher $fetcher): PublishedKeySetProvider
    {
        return new PublishedKeySetProvider($fetcher, $this->cache, $this->clock, new DateInterval('PT' . self::COOLDOWN . 'S'));
    }

    private static function jwksUri(): ClientUri
    {
        return new ClientUri(self::JWKS_URI);
    }

    private static function otherKeys(): ClientJwks
    {
        return new ClientJwks([[
            'kty' => 'EC',
            'crv' => 'P-256',
            'kid' => 'old-key',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
        ]]);
    }

    /**
     * @return list<string>
     */
    private static function urls(FakeClientJwksFetcher $fetcher): array
    {
        return array_map(static fn (ClientUri $uri): string => $uri->value, $fetcher->fetched);
    }
}
