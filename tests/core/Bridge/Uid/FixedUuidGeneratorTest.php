<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\Uid;

use Beffroi\Core\Bridge\Uid\FixedUuidGenerator;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;
use Symfony\Component\Uid\UuidV4;
use Symfony\Component\Uid\UuidV7;

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

    #[Test]
    public function whatItDrawsAsTimeOrderedIsAVersionSevenUuid(): void
    {
        // When / Then
        static::assertInstanceOf(UuidV7::class, new FixedUuidGenerator()->timeOrdered());
    }

    #[Test]
    public function whatItDrawsAsOpaqueIsAVersionFourUuid(): void
    {
        // When / Then
        static::assertInstanceOf(UuidV4::class, new FixedUuidGenerator()->opaque());
    }
}
