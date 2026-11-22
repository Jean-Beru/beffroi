<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Configuration;

use App\Configuration\MutualTlsSection;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 8705 §2, §5
 */
final class MutualTlsSectionTest extends TestCase
{
    #[Test]
    #[DataProvider('provideOrigins')]
    public function mutualTlsIsOnWhileAHostIsNamed(?string $origin, bool $on): void
    {
        // When / Then
        static::assertSame($on, MutualTlsSection::role($origin)->on);
    }

    /**
     * @return iterable<string, array{?string, bool}>
     */
    public static function provideOrigins(): iterable
    {
        yield 'none' => [null, false];
        yield 'the empty value of the image' => ['', false];
        yield 'a slash' => ['/', false];
        yield 'a host of its own' => ['https://mtls.op.test', true];
        yield 'the host of the issuer' => ['https://op.test/', true];
    }
}
