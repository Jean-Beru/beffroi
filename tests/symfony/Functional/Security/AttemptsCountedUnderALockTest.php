<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Security;

use App\Security\RateLimitedAttempts;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use ReflectionProperty;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\RateLimiter\RateLimiterFactory;

/**
 * RFC 4226 §7.3, Decision 0014
 */
final class AttemptsCountedUnderALockTest extends KernelTestCase
{
    #[Test]
    #[DataProvider('provideAttempts')]
    public function theAttemptsAreCountedUnderTheLocksOfTheDeployment(string $attempts): void
    {
        // Given
        $limiter = self::getContainer()->get($attempts);
        static::assertInstanceOf(RateLimitedAttempts::class, $limiter);
        $factory = new ReflectionProperty(RateLimitedAttempts::class, 'limiters')->getValue($limiter);
        static::assertInstanceOf(RateLimiterFactory::class, $factory);

        // When
        $locks = new ReflectionProperty(RateLimiterFactory::class, 'lockFactory')->getValue($factory);

        // Then
        static::assertSame(self::getContainer()->get('lock.factory'), $locks);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAttempts(): iterable
    {
        yield 'at a password' => ['beffroi.security.password_attempts'];
        yield 'at a code' => ['beffroi.security.code_attempts'];
        yield 'at the password in use, to change it' => ['beffroi.security.password_change_attempts'];
    }
}
