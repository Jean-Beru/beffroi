<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Claims;

use Beffroi\Oidc\Domain\Claims\SectorIdentifier;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Core §8.1
 */
final class SectorIdentifierTest extends TestCase
{
    #[Test]
    public function twoIdentifiersOfOneHostAreOneSector(): void
    {
        // When / Then
        static::assertTrue(new SectorIdentifier('rp.example')->equals(new SectorIdentifier('rp.example')));
    }

    #[Test]
    public function twoHostsAreTwoSectors(): void
    {
        // When / Then
        static::assertFalse(new SectorIdentifier('rp.example')->equals(new SectorIdentifier('other.example')));
    }

    #[Test]
    public function itIsWrittenAsTheHostItIs(): void
    {
        // When / Then
        static::assertSame('rp.example', (string) new SectorIdentifier('rp.example'));
    }

    #[Test]
    public function itRefusesAnEmptyHost(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A sector identifier is a host.');

        // When
        new SectorIdentifier('');
    }
}
