<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit\Exception;

use Beffroi\Xml\Core\Exception\LimitExceeded;
use Beffroi\Xml\Core\Exception\RefusedXml;
use function class_parents;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.7, I-7
 */
final class LimitExceededTest extends TestCase
{
    #[Test]
    public function itIsARefusedXml(): void
    {
        // When / Then
        static::assertContains(RefusedXml::class, class_parents(LimitExceeded::class));
    }
}
