<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Client;

use function array_map;
use DateInterval;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Client\ClientKeySetProvider;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientJwksCache;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientJwks;
use Heidi\Oidc\Domain\Client\ClientUri;
use Heidi\Oidc\Exception\ClientKeysUnavailableException;
use Heidi\Oidc\Tests\Fixture\ClientAssertions;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\FakeClientJwksFetcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * Where the keys of a client come from (RFC 7591 §2): the set it published inline, or the set read back
 * from its "jwks_uri", kept between requests and read again at most once per cooldown when an assertion
 * names a "kid" the kept set does not hold.
 */
final class ClientKeySetProviderTest extends TestCase
{
    private const string JWKS_URI = 'https://key.example/jwks';

    private const int COOLDOWN = 300;

    private Tenant $tenant;

    private MockClock $clock;

    private InMemoryClientJwksCache $cache;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->clock = new MockClock('2026-09-15T10:00:00+00:00');
        $this->cache = new InMemoryClientJwksCache();
    }

    #[Test]
    public function aSetPublishedInlineIsNeverFetched(): void
    {
        // Given
        $fetcher = new FakeClientJwksFetcher([ClientAssertions::publishedKeys()]);
        $client = Clients::withKeys($this->tenant);

        // When
        $keys = $this->provider($fetcher)->keysOf($client, ClientAssertions::KEY_ID);

        // Then
        static::assertSame($client->registration->jwks, $keys);
        static::assertSame([], $fetcher->fetched);
    }

    #[Test]
    public function aSetBehindAJwksUriIsFetchedOnce(): void
    {
        // Given
        $fetcher = new FakeClientJwksFetcher([ClientAssertions::publishedKeys()]);
        $provider = $this->provider($fetcher);
        $client = $this->remoteClient();
        $provider->keysOf($client, ClientAssertions::KEY_ID);

        // When
        $provider->keysOf($client, ClientAssertions::KEY_ID);

        // Then
        static::assertSame([self::JWKS_URI], self::urls($fetcher));
    }

    /**
     * A client that rotates a key is followed: the "kid" it now signs with is not in the kept set, and
     * the set is read again once the cooldown has passed.
     */
    #[Test]
    public function anUnknownKeyIdentifierCostsOneRefetch(): void
    {
        // Given
        $rotated = ClientAssertions::publishedKeys();
        $fetcher = new FakeClientJwksFetcher([self::otherKeys(), $rotated]);
        $provider = $this->provider($fetcher);
        $client = $this->remoteClient();
        $provider->keysOf($client, 'old-key');
        $this->clock->modify('+' . (self::COOLDOWN + 1) . ' seconds');

        // When
        $keys = $provider->keysOf($client, ClientAssertions::KEY_ID);

        // Then
        static::assertSame($rotated->keys, $keys->keys);
        static::assertCount(2, $fetcher->fetched);
    }

    /**
     * A client that signs with a key it never published cannot make the provider call it on every
     * request.
     */
    #[Test]
    public function aSecondUnknownKeyIdentifierInsideTheCooldownCostsNoRefetch(): void
    {
        // Given
        $fetcher = new FakeClientJwksFetcher([self::otherKeys(), self::otherKeys()]);
        $provider = $this->provider($fetcher);
        $client = $this->remoteClient();
        $provider->keysOf($client, 'old-key');
        $this->clock->modify('+' . (self::COOLDOWN + 1) . ' seconds');
        $provider->keysOf($client, ClientAssertions::KEY_ID);

        // When
        $provider->keysOf($client, ClientAssertions::KEY_ID);

        // Then
        static::assertCount(2, $fetcher->fetched);
    }

    /**
     * A signature that names no key is verified against everything the client published, so there is
     * nothing to read again.
     */
    #[Test]
    public function aSignatureThatNamesNoKeyCostsNoRefetch(): void
    {
        // Given
        $fetcher = new FakeClientJwksFetcher([self::otherKeys()]);
        $provider = $this->provider($fetcher);
        $client = $this->remoteClient();
        $provider->keysOf($client, null);
        $this->clock->modify('+1 day');

        // When
        $provider->keysOf($client, null);

        // Then
        static::assertCount(1, $fetcher->fetched);
    }

    /**
     * A "jwks_uri" that cannot be read is an authentication that fails, and nothing else.
     */
    #[Test]
    public function aJwksUriThatCannotBeReadIsRaised(): void
    {
        // Given
        $fetcher = new FakeClientJwksFetcher([ClientAssertions::publishedKeys()]);
        $fetcher->failure = new ClientKeysUnavailableException('https://key.example/jwks answered 500.');

        // Then
        $this->expectException(ClientKeysUnavailableException::class);
        $this->expectExceptionMessageIs('https://key.example/jwks answered 500.');

        // When
        $this->provider($fetcher)->keysOf($this->remoteClient(), ClientAssertions::KEY_ID);
    }

    private function provider(FakeClientJwksFetcher $fetcher): ClientKeySetProvider
    {
        return new ClientKeySetProvider($fetcher, $this->cache, $this->clock, new DateInterval('PT' . self::COOLDOWN . 'S'));
    }

    private function remoteClient(): Client
    {
        return Clients::withKeys($this->tenant, 'remote-client', jwksUri: new ClientUri(self::JWKS_URI));
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
