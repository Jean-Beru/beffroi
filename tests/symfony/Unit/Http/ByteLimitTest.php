<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Http;

use App\Http\ByteLimit;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * What a third party answers is read up to the bytes a document of its kind has any reason to be, and the read stops
 * at the first byte beyond.
 */
final class ByteLimitTest extends TestCase
{
    #[Test]
    #[DataProvider('provideBodies')]
    public function aBodyExceedsTheLimitAtTheFirstByteBeyondIt(string $body, bool $exceeds): void
    {
        // When / Then
        static::assertSame($exceeds, new ByteLimit(4)->isExceededBy($body));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideBodies(): iterable
    {
        yield 'shorter' => ['abc', false];
        yield 'as long' => ['abcd', false];
        yield 'a byte longer' => ['abcde', true];
    }
}
