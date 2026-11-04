<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client\Registration;

use Beffroi\Oidc\Application\Client\Registration\InitialAccessTokenAuthorization;
use Beffroi\Oidc\Application\Client\Registration\RegistrationAuthorizations;
use Beffroi\Oidc\Bridge\InMemory\InMemoryInitialAccessTokenRepository;
use Beffroi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * Decision 0009
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
