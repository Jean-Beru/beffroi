<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Value;

use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Value\Counts;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 7, M-17, M-15
 */
final class CountsTest extends TestCase
{
    /**
     * M-17
     */
    #[Test]
    public function itAcceptsACountAtItsBound(): void
    {
        // Then
        $this->expectNotToPerformAssertions();

        // When
        Counts::check(
            16,
            Counts::AUDIENCES,
            'An AudienceRestriction holds more than 16 Audience, the bound of section 7 (M-17).',
        );
    }

    /**
     * §9.2 row 36, M-17
     */
    #[Test]
    public function itRefusesACountOverItsBound(): void
    {
        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('An AudienceRestriction holds more than 16 Audience, the bound of section 7 (M-17).');

        // When
        Counts::check(
            17,
            Counts::AUDIENCES,
            'An AudienceRestriction holds more than 16 Audience, the bound of section 7 (M-17).',
        );
    }
}
