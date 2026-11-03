<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Client;

use DateInterval;
use App\Client\ClientJwksCache;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Client\CachedClientJwks;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Tests\Fixture\ClientAssertions;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * Where the keys read back from a "jwks_uri" are kept between requests, and what comes back from a pool
 * that outlived a deployment.
 */
final class ClientJwksCacheTest extends TestCase
{
    private const string JWKS_URI = 'https://key.example/jwks';

    private CacheItemPoolInterface $pool;

    private ClientJwksCache $cache;

    protected function setUp(): void
    {
        $this->pool = new ArrayAdapter();
        $this->cache = new ClientJwksCache($this->pool, new DateInterval('PT3600S'));
    }

    #[Test]
    public function aUrlNothingWasWrittenForHasNoKeys(): void
    {
        // When / Then
        static::assertNull($this->cache->read(self::jwksUri()));
    }

    #[Test]
    public function itReadsBackTheKeysAndTheMomentTheyWereRead(): void
    {
        // Given
        $fetchedAt = Fixtures::now();
        $this->cache->write(self::jwksUri(), new CachedClientJwks(ClientAssertions::publishedKeys(), $fetchedAt));

        // When
        $kept = $this->cache->read(self::jwksUri());

        // Then
        static::assertInstanceOf(CachedClientJwks::class, $kept);
        static::assertSame(ClientAssertions::publishedKeys()->keys, $kept->keys->keys);
        static::assertEquals($fetchedAt, $kept->fetchedAt);
    }

    /**
     * A pool outlives a deployment: what comes back from it is read as strictly as what comes back from
     * the party itself, and what cannot be read is read again from that party.
     */
    #[Test]
    public function whatWasKeptInAnotherShapeIsIgnored(): void
    {
        // Given
        $item = $this->pool->getItem(self::keyOf(self::jwksUri()));
        $item->set('from another version');
        $this->pool->save($item);

        // When / Then
        static::assertNull($this->cache->read(self::jwksUri()));
    }

    /**
     * A set is filed under the URL it was read from: what one URL answered is not what another did.
     */
    #[Test]
    public function theSetOfOneUrlIsNotTheSetOfAnother(): void
    {
        // Given
        $this->cache->write(self::jwksUri(), new CachedClientJwks(ClientAssertions::publishedKeys(), Fixtures::now()));

        // When / Then
        static::assertNull($this->cache->read(new ClientUri('https://other.example/jwks')));
    }

    private static function jwksUri(): ClientUri
    {
        return new ClientUri(self::JWKS_URI);
    }

    private static function keyOf(ClientUri $jwksUri): string
    {
        return 'beffroi.published_keys.' . hash('xxh128', $jwksUri->value);
    }
}
