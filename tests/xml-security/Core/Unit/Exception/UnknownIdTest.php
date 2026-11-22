<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit\Exception;

use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Exception\UnknownId;
use function class_parents;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.7, section 6.2
 */
final class UnknownIdTest extends TestCase
{
    #[Test]
    public function itIsARefusedXml(): void
    {
        // When / Then
        static::assertContains(RefusedXml::class, class_parents(UnknownId::class));
    }
}
