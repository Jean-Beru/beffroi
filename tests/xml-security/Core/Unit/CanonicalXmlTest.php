<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit;

use Beffroi\Xml\Core\CanonicalXml;
use Beffroi\Xml\Core\Exception\CanonicalizationFailed;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * I-13, CVE-2025-66578
 */
final class CanonicalXmlTest extends TestCase
{
    #[Test]
    public function itHoldsTheCanonicalBytes(): void
    {
        // When
        $canonical = new CanonicalXml('<a></a>');

        // Then
        static::assertSame('<a></a>', $canonical->bytes);
    }

    /**
     * §9.2 row 30, I-13
     */
    #[Test]
    public function itRefusesTheEmptyString(): void
    {
        // Then
        $this->expectException(CanonicalizationFailed::class);
        $this->expectExceptionMessageIs('The canonical form is empty (I-13).');

        // When
        new CanonicalXml('');
    }
}
