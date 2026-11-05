<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Http;

use App\Http\ByteLimit;
use App\Http\ReadWords;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * A bounded read names the address it refused, and says of the document only what its caller says.
 */
final class ReadWordsTest extends TestCase
{
    #[Test]
    public function aRedirectNamesTheAddressAndTheAdviceOfTheCaller(): void
    {
        // When / Then
        static::assertSame(
            'https://rp.example.com/keys redirects, and no outbound request follows a redirect; publish the keys there.',
            new ReadWords('publish the keys there.', '')->redirected('https://rp.example.com/keys'),
        );
    }

    #[Test]
    public function anExcessNamesTheAddressAndTheLimitInTheSentenceOfTheCaller(): void
    {
        // When / Then
        static::assertSame(
            'https://rp.example.com/keys holds more than 4 bytes.',
            new ReadWords('', '%s holds more than %d bytes.')->exceeded('https://rp.example.com/keys', new ByteLimit(4)),
        );
    }
}
