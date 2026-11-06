<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Key;

use Beffroi\Core\Application\Key\MessageKeysInService;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryKeyPairGenerator;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\HeldKeys;
use Beffroi\Core\Tests\Fixture\Keys;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0020
 */
final class MessageKeysInServiceTest extends TestCase
{
    #[Test]
    public function eachMessageKeyInServiceIsOpenedAndNoOtherKey(): void
    {
        // Given
        $keys = new HeldKeys(Fixtures::tenant());
        $keys->active(Algorithms::messageSeal(), Keys::messagePair());
        $keys->staged(Algorithms::messageSeal(), Keys::otherMessagePair());
        $keys->retired(Algorithms::messageSeal(), new JwtLibraryKeyPairGenerator(Algorithms::everyUse())->generate(Algorithms::messageSeal()));
        $keys->active(Algorithms::ecdhEsA256Kw(), Keys::encryptionPair());
        $keys->active(Algorithms::rs256(), Keys::pair());

        // When
        new MessageKeysInService($keys->repository, $keys->provider)->open($keys->tenant);

        // Then
        static::assertSame(2, $keys->sealer->unsealed);
    }
}
