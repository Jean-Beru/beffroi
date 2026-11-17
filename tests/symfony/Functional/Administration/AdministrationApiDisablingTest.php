<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Administration;

use Beffroi\Core\Domain\Event\PersonDisabled;
use Beffroi\Core\Domain\Event\PersonEnabled;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\SessionEnd;
use PHPUnit\Framework\Attributes\Test;
use function count;
use function sprintf;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0038: an administrator disables a person, who can no longer sign in and whose sessions end, and enables them
 * again, through the administration API on the use cases of the commands of the console, each an act of the person
 * that names the administrator.
 */
final class AdministrationApiDisablingTest extends AdministrationTestCase
{
    #[Test]
    public function aPersonAnAdministratorDisabledIsAnsweredDisabled(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api(self::disabledPath($bob), $token, method: 'PUT');

        // Then
        static::assertSame(
            [Response::HTTP_OK, false, false],
            [$response->getStatusCode(), self::members($response, ['enabled'])[0], self::personAgain($bob)->isEnabled()],
        );
    }

    #[Test]
    public function everySessionOfTheDisabledPersonEndsInTheNameOfTheAdministrator(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $session = $this->signIn($bob);
        $token = $this->administratorToken(self::user('alice'));

        // When
        $this->api(self::disabledPath($bob), $token, method: 'PUT');

        // Then
        static::assertSame(SessionEnd::Administrator, self::sessionAgain($session)->endedBy);
    }

    #[Test]
    public function theDisablingIsAnActOfThePersonThatNamesTheAdministrator(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $token = $this->administratorToken(self::user('alice'));

        // When
        $this->api(self::disabledPath($bob), $token, method: 'PUT');

        // Then
        static::assertSame([['bob-subject', 'alice-subject']], self::authored(PersonDisabled::NAME));
    }

    #[Test]
    public function aPersonDisabledAlreadyIsAnsweredAsTheyAre(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $token = $this->administratorToken(self::user('alice'));
        $this->api(self::disabledPath($bob), $token, method: 'PUT');

        // When
        $response = $this->api(self::disabledPath($bob), $token, method: 'PUT');

        // Then
        static::assertSame([Response::HTTP_OK, 1], [$response->getStatusCode(), count(self::authored(PersonDisabled::NAME))]);
    }

    #[Test]
    public function anAdministratorDoesNotDisableTheAccountTheyActWith(): void
    {
        // Given
        $alice = self::user('alice');
        $token = $this->administratorToken($alice);

        // When
        $response = $this->api(self::disabledPath($alice), $token, method: 'PUT');

        // Then
        static::assertSame(
            [Response::HTTP_CONFLICT, 'conflict', true, []],
            [$response->getStatusCode(), self::members($response, ['error'])[0], self::personAgain($alice)->isEnabled(), self::authored(PersonDisabled::NAME)],
        );
    }

    #[Test]
    public function anAdministratorEnablesAPersonAgain(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $token = $this->administratorToken(self::user('alice'));
        $this->api(self::disabledPath($bob), $token, method: 'PUT');

        // When
        $response = $this->api(self::disabledPath($bob), $token, method: 'DELETE');

        // Then
        static::assertSame(
            [Response::HTTP_OK, true, true],
            [$response->getStatusCode(), self::members($response, ['enabled'])[0], self::personAgain($bob)->isEnabled()],
        );
    }

    #[Test]
    public function theEnablingIsAnActOfThePersonThatNamesTheAdministrator(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $token = $this->administratorToken(self::user('alice'));
        $this->api(self::disabledPath($bob), $token, method: 'PUT');

        // When
        $this->api(self::disabledPath($bob), $token, method: 'DELETE');

        // Then
        static::assertSame([['bob-subject', 'alice-subject']], self::authored(PersonEnabled::NAME));
    }

    #[Test]
    public function aPersonTheTenantDoesNotHoldIsNotFound(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api(sprintf('/users/%s/disabled', Uuid::v7()->toRfc4122()), $token, method: 'PUT');

        // Then
        static::assertSame(
            [Response::HTTP_NOT_FOUND, 'not_found', []],
            [$response->getStatusCode(), self::members($response, ['error'])[0], self::authored(PersonDisabled::NAME)],
        );
    }

    private static function disabledPath(User $person): string
    {
        return sprintf('/users/%s/disabled', $person->id->toRfc4122());
    }
}
