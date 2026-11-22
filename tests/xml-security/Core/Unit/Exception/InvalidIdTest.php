<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit\Exception;

use Beffroi\Xml\Core\Exception\InvalidId;
use Beffroi\Xml\Core\Exception\RefusedXml;
use function class_parents;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.7, I-8
 */
final class InvalidIdTest extends TestCase
{
    #[Test]
    public function itIsARefusedXml(): void
    {
        // When / Then
        static::assertContains(RefusedXml::class, class_parents(InvalidId::class));
    }
}
