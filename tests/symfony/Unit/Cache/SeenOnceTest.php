<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Cache;

use App\Cache\SeenOnce;
use App\Tests\Symfony\Fixture\PoolWatchingItsLocks;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Lock\LockFactory;
use Symfony\Component\Lock\Store\InMemoryStore;

/**
 * RFC 7523 §3, RFC 9449 §11.1
 */
final class SeenOnceTest extends TestCase
{
    private const string KEY = 'beffroi.client_assertions.the-identifier';

    private LockFactory $locks;

    private DateTimeImmutable $expiresAt;

    protected function setUp(): void
    {
        $this->locks = new LockFactory(new InMemoryStore());
        // The pool expires its items against the wall clock, so the identifier expires an hour ahead of it.
        $this->expiresAt = new DateTimeImmutable('+1 hour');
    }

    #[Test]
    public function anIdentifierNotSeenYetIsTaken(): void
    {
        // Given
        $seen = new SeenOnce(new ArrayAdapter(), $this->locks);

        // When / Then
        static::assertTrue($seen->remember(self::KEY, $this->expiresAt));
    }

    #[Test]
    public function anIdentifierSeenAlreadyIsRefused(): void
    {
        // Given
        $seen = new SeenOnce(new ArrayAdapter(), $this->locks);
        $seen->remember(self::KEY, $this->expiresAt);

        // When / Then
        static::assertFalse($seen->remember(self::KEY, $this->expiresAt));
    }

    #[Test]
    public function theIdentifierIsReadAndWrittenUnderTheLockOfItsKey(): void
    {
        // Given
        $pool = new PoolWatchingItsLocks($this->locks);
        $seen = new SeenOnce($pool, $this->locks);

        // When
        $seen->remember(self::KEY, $this->expiresAt);

        // Then
        static::assertSame([false, false], $pool->lockFree);
    }

    #[Test]
    public function theLockOfTheKeyIsReleasedOnceTheIdentifierIsTaken(): void
    {
        // Given
        $seen = new SeenOnce(new ArrayAdapter(), $this->locks);

        // When
        $seen->remember(self::KEY, $this->expiresAt);

        // Then
        static::assertTrue($this->locks->createLock(self::KEY)->acquire());
    }
}
