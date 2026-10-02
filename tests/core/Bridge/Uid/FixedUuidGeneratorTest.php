<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\Uid;

use Beffroi\Core\Bridge\Uid\FixedUuidGenerator;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;
use Symfony\Component\Uid\UuidV4;
use Symfony\Component\Uid\UuidV7;

/**
 * The identifiers a test writes down: what it wrote first, then a sequence that repeats nothing.
 */
final class FixedUuidGeneratorTest extends TestCase
{
    #[Test]
    public function itHandsBackWhatItWasGiven(): void
    {
        // Given
        $chosen = Uuid::fromString('0199a0d4-0000-7000-8000-000000000042');
        $uuids = new FixedUuidGenerator([$chosen]);

        // When / Then
        static::assertTrue($chosen->equals($uuids->timeOrdered()));
    }

    #[Test]
    public function itDrawsOnWhenWhatItWasGivenRunsOut(): void
    {
        // Given
        $uuids = new FixedUuidGenerator();

        // When / Then
        static::assertFalse($uuids->timeOrdered()->equals($uuids->timeOrdered()));
    }

    /**
     * What it draws on its own is ordered in time, as the port asks of the identifier of a row.
     */
    #[Test]
    public function whatItDrawsAsTimeOrderedIsAVersionSevenUuid(): void
    {
        // When / Then
        static::assertInstanceOf(UuidV7::class, new FixedUuidGenerator()->timeOrdered());
    }

    /**
     * What it draws on its own says nothing of when it was drawn, as the port asks of an opaque one.
     */
    #[Test]
    public function whatItDrawsAsOpaqueIsAVersionFourUuid(): void
    {
        // When / Then
        static::assertInstanceOf(UuidV4::class, new FixedUuidGenerator()->opaque());
    }
}
