<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Client\Registration;

use Heidi\Oidc\Application\Client\Registration\InitialAccessTokenAuthorization;
use Heidi\Oidc\Application\Client\Registration\RegistrationAuthorizations;
use Heidi\Oidc\Bridge\InMemory\InMemoryInitialAccessTokenRepository;
use Heidi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * Decision 0009: what authorises a registration is a class per mode, and the policy of a tenant names
 * one of them. Nothing here compares a mode to a literal: the classes name themselves and this matches
 * the name, so a mode the provider gains is a class added and a line of wiring.
 */
final class RegistrationAuthorizationsTest extends TestCase
{
    #[Test]
    public function thePolicyNamesTheWiredModeThatServesIt(): void
    {
        // Given
        $mode = self::initialAccessToken();
        $modes = new RegistrationAuthorizations([$mode]);

        // When
        $authorization = $modes->authorizing(new ClientRegistrationPolicy(InitialAccessTokenAuthorization::MODE));

        // Then
        static::assertSame($mode, $authorization);
    }

    /**
     * A deployment that wired one thing and wrote another is told which modes it wired.
     */
    #[Test]
    public function aModeNothingServesNamesWhatIsWired(): void
    {
        // Given
        $modes = new RegistrationAuthorizations([self::initialAccessToken()]);

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('The registration policy names the mode "attested", which nothing wired here serves; this provider serves initial_access_token.');

        // When
        $modes->authorizing(new ClientRegistrationPolicy('attested'));
    }

    /**
     * A deployment with no mode at all is told so rather than shown an empty list.
     */
    #[Test]
    public function aProviderWiredWithNoModeSaysSo(): void
    {
        // Given
        $modes = new RegistrationAuthorizations([]);

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('The registration policy names the mode "initial_access_token", which nothing wired here serves; this provider serves none.');

        // When
        $modes->authorizing(new ClientRegistrationPolicy(InitialAccessTokenAuthorization::MODE));
    }

    /**
     * Two classes answering to one name is a wiring nobody can read, and it is refused at the wiring.
     */
    #[Test]
    public function twoModesOfOneNameAreRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The client registration mode "initial_access_token" is wired twice.');

        // When
        new RegistrationAuthorizations([self::initialAccessToken(), self::initialAccessToken()]);
    }

    private static function initialAccessToken(): InitialAccessTokenAuthorization
    {
        return new InitialAccessTokenAuthorization(
            new InMemoryInitialAccessTokenRepository(),
            new MockClock('2026-09-15T10:00:00+00:00'),
        );
    }
}
