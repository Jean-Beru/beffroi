<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Key;

use Beffroi\Core\Application\Key\ApplicationServerKeysInService;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryKeyPairGenerator;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\HeldKeys;
use Beffroi\Core\Tests\Fixture\Keys;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 8292 §2
 */
final class ApplicationServerKeysInServiceTest extends TestCase
{
    #[Test]
    public function eachApplicationServerKeyInServiceIsOpenedAndNoOtherKey(): void
    {
        // Given
        $keys = new HeldKeys(Fixtures::tenant());
        $generator = new JwtLibraryKeyPairGenerator(Algorithms::everyUse());
        $keys->active(Algorithms::vapid(), Keys::applicationServerPair());
        $keys->staged(Algorithms::vapid(), $generator->generate(Algorithms::vapid()));
        $keys->retired(Algorithms::vapid(), $generator->generate(Algorithms::vapid()));
        $keys->active(Algorithms::messageSeal(), Keys::messagePair());
        $keys->active(Algorithms::rs256(), Keys::pair());

        // When
        new ApplicationServerKeysInService($keys->repository, $keys->provider)->open($keys->tenant);

        // Then
        static::assertSame(2, $keys->sealer->unsealed);
    }
}
