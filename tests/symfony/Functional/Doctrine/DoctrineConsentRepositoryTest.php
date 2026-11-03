<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientPresentation;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Tests\Fixture\Methods;
use Beffroi\Oidc\Tests\Fixture\Shapes;
use function array_map;
use Beffroi\Oidc\Port\ActiveConsentsInterface;
use Beffroi\Oidc\Port\ConsentRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §4.3, §5.3: the consent in force between a user and a client is the active one granted
 * last; a superseded one stays, revoked.
 */
final class DoctrineConsentRepositoryTest extends DatabaseTestCase
{
    #[Test]
    public function aConsentComesBackAsItWasGranted(): void
    {
        // Given
        $user = self::user();
        $client = self::client();
        $consent = new Consent(Uuid::v7(), $user, $client, new Scopes([new Scope('openid'), new Scope('profile')]), self::now());
        self::consents()->save($consent);
        self::reload();

        // When
        $found = self::consents()->findActive($user, $client) ?? static::fail('The consent was not stored.');

        // Then
        static::assertTrue($found->id->equals($consent->id));
        static::assertTrue($found->user->id->equals($user->id));
        static::assertTrue($found->tenant->id->equals(self::tenant()->id));
        static::assertSame('oidc-demo', $found->clientId);
        static::assertSame('oidc-demo', $found->client->registration->clientId);
        static::assertTrue($found->isFor($user, $client));
        static::assertEquals([new Scope('openid'), new Scope('profile')], $found->scopes->all);
        static::assertEquals(self::now(), $found->grantedAt);
        static::assertNull($found->revokedAt);
        static::assertTrue($found->isActive());
    }

    #[Test]
    public function theConsentInForceIsTheActiveOneGrantedLast(): void
    {
        // Given
        $alice = self::user();
        $demo = self::client();
        $superseded = new Consent(Uuid::v7(), $alice, $demo, new Scopes([new Scope('openid')]), self::now()->modify('-1 day'));
        $superseded->revoke(self::now());
        self::consents()->save($superseded);
        $latest = new Consent(Uuid::v7(), $alice, $demo, new Scopes([new Scope('openid'), new Scope('email')]), self::now());
        self::consents()->save($latest);
        self::consents()->save(new Consent(Uuid::v7(), $alice, $demo, new Scopes([new Scope('openid'), new Scope('profile')]), self::now()->modify('-1 hour')));
        self::consents()
            ->save(new Consent(Uuid::v7(), self::user('bob', 'bob-subject'), $demo, new Scopes([new Scope('openid')]), self::now()->modify('+1 hour')));
        self::consents()->save(new Consent(Uuid::v7(), $alice, self::client('native-app'), new Scopes([new Scope('openid')]), self::now()->modify('+1 hour')));
        self::reload();

        // When
        $found = self::consents()->findActive($alice, $demo);

        // Then
        static::assertTrue($latest->id->equals($found?->id));
    }

    #[Test]
    public function aUserWithoutConsentHasNoneInForce(): void
    {
        // Given
        $demo = self::client();
        self::consents()->save(new Consent(Uuid::v7(), self::user(), $demo, new Scopes([new Scope('openid')]), self::now()));
        self::reload();

        // When / Then
        static::assertNull(self::consents()->findActive(self::user('carol', 'carol-subject'), $demo));
    }

    #[Test]
    public function aRevocationIsWrittenOnSave(): void
    {
        // Given
        $user = self::user();
        $client = self::client();
        $consent = new Consent(Uuid::v7(), $user, $client, new Scopes([new Scope('openid')]), self::now());
        self::consents()->save($consent);
        $consent->revoke(self::now()->modify('+1 hour'));
        self::consents()->save($consent);
        self::reload();

        // When / Then
        static::assertNull(self::consents()->findActive($user, $client));
        static::assertEquals(self::now()->modify('+1 hour'), self::entityManager()->find(Consent::class, $consent->id)?->revokedAt);
    }

    /**
     * What the page of the account reads: one line per client, the most recently granted first, the
     * consents of another user left out.
     */
    #[Test]
    public function theConsentsInForceAreListedForTheirUser(): void
    {
        // Given
        $alice = self::user();
        self::consents()->save(new Consent(Uuid::v7(), $alice, self::client(), new Scopes([new Scope('openid')]), self::now()->modify('-1 day')));
        self::consents()->save(new Consent(Uuid::v7(), $alice, self::client('native-app'), new Scopes([new Scope('openid')]), self::now()));
        self::consents()->save(new Consent(Uuid::v7(), self::user('bob', 'bob-subject'), self::client(), new Scopes([new Scope('openid')]), self::now()));
        self::reload();

        // When
        $inForce = self::activeConsents()->activeOf($alice);

        // Then
        static::assertSame(['native-app', 'oidc-demo'], array_map(static fn (Consent $consent): string => $consent->clientId, $inForce));
    }

    #[Test]
    public function aConsentTakenBackIsNotInForce(): void
    {
        // Given
        $alice = self::user();
        $consent = new Consent(Uuid::v7(), $alice, self::client(), new Scopes([new Scope('openid')]), self::now());
        $consent->revoke(self::now()->modify('+1 hour'));
        self::consents()->save($consent);
        self::reload();

        // When / Then
        static::assertSame([], self::activeConsents()->activeOf($alice));
    }

    /**
     * A client the configuration no longer declares leaves rows behind; a consent of nobody is not one.
     */
    #[Test]
    public function aConsentOfAClientNoLongerRegisteredIsNotListed(): void
    {
        // Given
        $alice = self::user();
        $ghost = new Client(
            self::tenant(),
            new ClientRegistration(
                'ghost',
                new ClientPresentation('Removed client'),
                Methods::none(),
                false,
                [new RedirectUri('https://ghost.example/callback')],
                Shapes::jwt(),
            ),
        );
        self::consents()->save(new Consent(Uuid::v7(), $alice, $ghost, new Scopes([new Scope('openid')]), self::now()));
        self::reload();

        // When / Then
        static::assertSame([], self::activeConsents()->activeOf($alice));
    }

    private static function activeConsents(): ActiveConsentsInterface
    {
        return self::service('test.beffroi.active_consents', ActiveConsentsInterface::class);
    }

    private static function consents(): ConsentRepositoryInterface
    {
        return self::service('test.beffroi.consents', ConsentRepositoryInterface::class);
    }
}
