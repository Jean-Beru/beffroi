<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Configuration;

use App\Configuration\MailSection;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0048, Decision 0030
 */
final class MailSectionTest extends TestCase
{
    #[Test]
    #[DataProvider('provideDsns')]
    public function mailIsOnWhileADsnIsNamed(?string $dsn, bool $on): void
    {
        // When / Then
        static::assertSame($on, MailSection::role($dsn)->on);
    }

    /**
     * @return iterable<string, array{?string, bool}>
     */
    public static function provideDsns(): iterable
    {
        yield 'none' => [null, false];
        yield 'a server' => ['smtp://mail.op.test:587', true];
    }
}
