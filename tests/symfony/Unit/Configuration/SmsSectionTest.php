<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Configuration;

use App\Configuration\SmsSection;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0048, Decision 0030
 */
final class SmsSectionTest extends TestCase
{
    #[Test]
    #[DataProvider('provideDsns')]
    public function smsIsOnWhileADsnIsNamed(?string $dsn, bool $on): void
    {
        // When / Then
        static::assertSame($on, SmsSection::role($dsn)->on);
    }

    /**
     * @return iterable<string, array{?string, bool}>
     */
    public static function provideDsns(): iterable
    {
        yield 'none' => [null, false];
        yield 'a provider' => ['null://null', true];
    }
}
