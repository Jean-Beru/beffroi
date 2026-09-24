<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Client;

use Heidi\Bundle\Client\ClientJwksCache;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Client\CachedClientJwks;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Tests\Fixture\ClientAssertions;
use Heidi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * Where the keys read back from a client's "jwks_uri" are kept between requests, and what comes back
 * from a pool that outlived a deployment.
 */
final class ClientJwksCacheTest extends TestCase
{
    private CacheItemPoolInterface $pool;

    private ClientJwksCache $cache;

    private Client $client;

    protected function setUp(): void
    {
        $this->pool = new ArrayAdapter();
        $this->cache = new ClientJwksCache($this->pool, 3600);
        $this->client = Clients::withKeys(Fixtures::tenant());
    }

    #[Test]
    public function aClientNothingWasWrittenForHasNoKeys(): void
    {
        // When / Then
        static::assertNull($this->cache->read($this->client));
    }

    #[Test]
    public function itReadsBackTheKeysAndTheMomentTheyWereRead(): void
    {
        // Given
        $fetchedAt = Fixtures::now();
        $this->cache->write($this->client, new CachedClientJwks(ClientAssertions::publishedKeys(), $fetchedAt));

        // When
        $kept = $this->cache->read($this->client);

        // Then
        static::assertInstanceOf(CachedClientJwks::class, $kept);
        static::assertSame(ClientAssertions::publishedKeys()->keys, $kept->keys->keys);
        static::assertEquals($fetchedAt, $kept->fetchedAt);
    }

    /**
     * A pool outlives a deployment: what comes back from it is read as strictly as what comes back from
     * the client itself, and what cannot be read is read again from the client.
     */
    #[Test]
    public function whatWasKeptInAnotherShapeIsIgnored(): void
    {
        // Given
        $item = $this->pool->getItem(self::keyOf($this->client));
        $item->set('from another version');
        $this->pool->save($item);

        // When / Then
        static::assertNull($this->cache->read($this->client));
    }

    /**
     * The clients of two tenants do not share a set.
     */
    #[Test]
    public function theSetOfAClientIsScopedByItsTenant(): void
    {
        // Given
        $this->cache->write($this->client, new CachedClientJwks(ClientAssertions::publishedKeys(), Fixtures::now()));

        // When / Then
        static::assertNull($this->cache->read(Clients::withKeys(Fixtures::tenant('other', 'https://id.other.example'))));
    }

    private static function keyOf(Client $client): string
    {
        return 'heidi.client_keys.' . hash('xxh128', $client->tenant->id->toRfc4122() . '|' . $client->registration->clientId);
    }
}
