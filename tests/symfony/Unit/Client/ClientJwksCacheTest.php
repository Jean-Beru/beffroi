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
