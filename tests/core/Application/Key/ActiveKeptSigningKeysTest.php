<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Key;

use Beffroi\Core\Application\Key\ActiveKeptSigningKeys;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\HeldKeys;
use Beffroi\Core\Tests\Fixture\KeptSigning;
use Beffroi\Core\Tests\Fixture\Keys;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Architecture §3.3
 */
final class ActiveKeptSigningKeysTest extends TestCase
{
    #[Test]
    public function theActiveKeyOfEachKeptAlgorithmIsOpenedAndNoOtherKey(): void
    {
        // Given
        $keys = new HeldKeys(Fixtures::tenant());
        $keys->active(new KeptSigning(), Keys::otherPair());
        $keys->active(Algorithms::rs256(), Keys::pair());

        // When
        new ActiveKeptSigningKeys([new KeptSigning()], $keys->provider)->open($keys->tenant);

        // Then
        static::assertSame(1, $keys->sealer->unsealed);
    }

    #[Test]
    public function aKeptAlgorithmWithNoActiveKeyHasNothingToOpen(): void
    {
        // Given
        $keys = new HeldKeys(Fixtures::tenant());

        // When
        new ActiveKeptSigningKeys([new KeptSigning()], $keys->provider)->open($keys->tenant);

        // Then
        static::assertSame(0, $keys->sealer->unsealed);
    }
}
