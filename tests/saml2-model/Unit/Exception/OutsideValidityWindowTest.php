<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Exception;

use Beffroi\Saml2\Model\Exception\OutsideValidityWindow;
use Beffroi\Saml2\Model\Exception\MessageRefused;
use function class_parents;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.8, M-7
 */
final class OutsideValidityWindowTest extends TestCase
{
    #[Test]
    public function itIsAMessageRefused(): void
    {
        // When / Then
        static::assertContains(MessageRefused::class, class_parents(OutsideValidityWindow::class));
    }
}
