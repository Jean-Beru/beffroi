<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Http;

use App\Http\QrCode;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_starts_with;

/**
 * Architecture §5.2
 */
final class QrCodeTest extends TestCase
{
    #[Test]
    public function itDrawsAnSvgDocumentWithoutTheXmlDeclaration(): void
    {
        // When
        $svg = new QrCode()->svg('otpauth://totp/ACME:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME');

        // Then
        static::assertTrue(str_starts_with($svg, '<svg '), $svg);
        static::assertStringContainsString('width="240"', $svg);
        static::assertStringContainsString('<path ', $svg);
        static::assertStringNotContainsString('<?xml', $svg);
        static::assertStringNotContainsString('GEZDGNBVGY3TQOJQ', $svg, 'The SVG holds squares, never the text.');
    }
}
