<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Claims;

use Heidi\Oidc\Domain\Claims\SectorIdentifier;
use Heidi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Core §8.1: the administrative domain a set of clients shares, which is a host and nothing else.
 * Where it is read from is the wiring's (`SectorIdentifiers`).
 */
final class SectorIdentifierTest extends TestCase
{
    /**
     * Two clients of one sector see a user under one identifier: it is the sector that decides and not the
     * client, so two identifiers of one host are one sector.
     */
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

    /**
     * It is what a pairwise identifier is computed per, so it is written as it is compared: the host, and
     * never a URL it was read out of.
     */
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
