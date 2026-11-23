<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Security;

use App\Confirmation\RateLimitedConfirmationSends;
use Beffroi\Core\Port\ConfirmationSendLimiterInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use ReflectionProperty;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\RateLimiter\RateLimiterFactory;

/**
 * Decision 0014
 */
final class ConfirmationSendsCountedUnderALockTest extends KernelTestCase
{
    #[Test]
    #[DataProvider('provideBudgets')]
    public function theSendsAreCountedUnderTheLocksOfTheDeployment(string $budget): void
    {
        // Given
        $sends = self::getContainer()->get(ConfirmationSendLimiterInterface::class);
        static::assertInstanceOf(RateLimitedConfirmationSends::class, $sends);
        $factory = new ReflectionProperty(RateLimitedConfirmationSends::class, $budget)->getValue($sends);
        static::assertInstanceOf(RateLimiterFactory::class, $factory);

        // When
        $locks = new ReflectionProperty(RateLimiterFactory::class, 'lockFactory')->getValue($factory);

        // Then
        static::assertSame(self::getContainer()->get('lock.factory'), $locks);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideBudgets(): iterable
    {
        yield 'of a person' => ['persons'];
        yield 'to an address' => ['addresses'];
    }
}
