<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Administration;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Event\ConsentRevoked;
use Beffroi\Oidc\Domain\Event\ConsentsReadByAnAdministrator;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Port\ActiveConsentsInterface;
use Beffroi\Oidc\Port\ConsentRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use function array_map;
use function is_array;
use function sprintf;
use Symfony\Component\Clock\Clock;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0038: an administrator reads the applications a person agreed to and takes a consent back, through the
 * administration API on what the commands of the console call, each an act of the person that names them.
 */
final class AdministrationApiConsentsTest extends AdministrationTestCase
{
    #[Test]
    public function theConsentsOfAPersonAreAnsweredWithWhatEachApplicationWasGranted(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $consent = self::agree($bob);
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api(self::consentsPath($bob), $token);

        // Then
        $consents = self::members($response, ['consents'])[0];
        static::assertIsArray($consents);
        static::assertSame(
            [[$consent->id->toRfc4122(), 'oidc-demo', 'openid profile']],
            array_map(
                static fn (mixed $read): array => is_array($read) ? [$read['id'] ?? null, $read['client_id'] ?? null, $read['scope'] ?? null] : [],
                $consents,
            ),
        );
    }

    /**
     * Decision 0022
     */
    #[Test]
    public function readingTheConsentsIsAnActOfThePersonThatNamesTheAdministrator(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        self::agree($bob);
        $token = $this->administratorToken(self::user('alice'));

        // When
        $this->api(self::consentsPath($bob), $token);

        // Then
        static::assertSame([['bob-subject', 'alice-subject']], self::authored(ConsentsReadByAnAdministrator::NAME));
    }

    #[Test]
    public function anAdministratorTakesAConsentBack(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $consent = self::agree($bob);
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api(self::consentPath($bob, $consent), $token, method: 'DELETE');

        // Then
        self::reload();
        static::assertSame(
            [Response::HTTP_OK, []],
            [$response->getStatusCode(), self::service('test.beffroi.active_consents', ActiveConsentsInterface::class)->activeOf(self::personAgain($bob))],
        );
    }

    #[Test]
    public function takingAConsentBackIsAnActOfThePersonThatNamesTheAdministrator(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $consent = self::agree($bob);
        $token = $this->administratorToken(self::user('alice'));

        // When
        $this->api(self::consentPath($bob, $consent), $token, method: 'DELETE');

        // Then
        static::assertSame([['bob-subject', 'alice-subject']], self::authored(ConsentRevoked::NAME));
    }

    #[Test]
    public function aConsentThePersonDoesNotHoldIsNotFound(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $carol = self::user('carol', 'carol-subject');
        $hers = self::agree($carol);
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api(self::consentPath($bob, $hers), $token, method: 'DELETE');

        // Then
        static::assertSame([Response::HTTP_NOT_FOUND, []], [$response->getStatusCode(), self::authored(ConsentRevoked::NAME)]);
    }

    #[Test]
    public function aPersonTheTenantDoesNotHoldIsNotFound(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api(sprintf('/users/%s/consents', Uuid::v7()->toRfc4122()), $token);

        // Then
        static::assertSame([Response::HTTP_NOT_FOUND, []], [$response->getStatusCode(), self::authored(ConsentsReadByAnAdministrator::NAME)]);
    }

    private static function agree(User $user): Consent
    {
        $consent = new Consent(
            Uuid::v7(),
            $user,
            self::client(),
            new Scopes([new Scope('openid'), new Scope('profile')]),
            Clock::get()->now(),
        );
        self::service('test.beffroi.consents', ConsentRepositoryInterface::class)->save($consent);

        return $consent;
    }

    private static function consentsPath(User $person): string
    {
        return sprintf('/users/%s/consents', $person->id->toRfc4122());
    }

    private static function consentPath(User $person, Consent $consent): string
    {
        return sprintf('/users/%s/consents/%s', $person->id->toRfc4122(), $consent->id->toRfc4122());
    }
}
