<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Event;

use Beffroi\Core\Domain\Event\AuthenticationFailed;
use Beffroi\Core\Domain\Event\AuthenticationFailureReason;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class AuthenticationFailedTest extends TestCase
{
    /**
     * Decision 0062
     */
    #[Test]
    public function itSaysWhyItRefusedAndTheMethodItRefused(): void
    {
        // When
        $event = new AuthenticationFailed(
            Fixtures::now(),
            Fixtures::tenant(),
            Fixtures::context(),
            AuthenticationMethod::password(),
            AuthenticationFailureReason::InvalidCredential,
            'alice',
            Fixtures::user(),
        );

        // Then
        static::assertSame(['invalid_credential', 'pwd'], [$event->refusalReason(), $event->refusedMethod()]);
    }

    /**
     * Decision 0062
     */
    #[Test]
    public function aRefusalBeforeAnyMethodNamesNone(): void
    {
        // Given
        $event = new AuthenticationFailed(
            Fixtures::now(),
            Fixtures::tenant(),
            Fixtures::context(),
            null,
            AuthenticationFailureReason::UnknownUser,
            'nobody',
            null,
        );

        // When / Then
        static::assertNull($event->refusedMethod());
    }
}
