<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine;

use Heidi\Oidc\Domain\Consent\Consent;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Port\ConsentRepositoryInterface;
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
        $consents = self::consents();
        $user = self::user();
        $client = self::client();
        $consent = new Consent(Uuid::v7(), $user, $client, [new Scope('openid'), new Scope('profile')], self::now());
        $consents->save($consent);
        self::reload();

        $found = $consents->findActive($user, $client) ?? static::fail('The consent was not stored.');

        static::assertTrue($found->id->equals($consent->id));
        static::assertTrue($found->user->id->equals($user->id));
        static::assertTrue($found->tenant->id->equals(self::tenant()->id));
        static::assertSame('oidc-demo', $found->clientId);
        static::assertSame('oidc-demo', $found->client->clientId);
        static::assertTrue($found->isFor($user, $client));
        static::assertEquals([new Scope('openid'), new Scope('profile')], $found->scopes);
        static::assertEquals(self::now(), $found->grantedAt);
        static::assertNull($found->revokedAt);
        static::assertTrue($found->isActive());
    }

    #[Test]
    public function theConsentInForceIsTheActiveOneGrantedLast(): void
    {
        $consents = self::consents();
        $alice = self::user();
        $bob = self::user('bob', 'bob-subject');
        $demo = self::client();
        $native = self::client('native-app');
        $superseded = new Consent(Uuid::v7(), $alice, $demo, [new Scope('openid')], self::now()->modify('-1 day'));
        $superseded->revoke(self::now());
        $consents->save($superseded);
        $latest = new Consent(Uuid::v7(), $alice, $demo, [new Scope('openid'), new Scope('email')], self::now());
        $consents->save($latest);
        $older = new Consent(Uuid::v7(), $alice, $demo, [new Scope('openid'), new Scope('profile')], self::now()->modify('-1 hour'));
        $consents->save($older);
        $consents->save(new Consent(Uuid::v7(), $bob, $demo, [new Scope('openid')], self::now()->modify('+1 hour')));
        $consents->save(new Consent(Uuid::v7(), $alice, $native, [new Scope('openid')], self::now()->modify('+1 hour')));
        self::reload();

        static::assertTrue($latest->id->equals($consents->findActive($alice, $demo)?->id));
        static::assertNull($consents->findActive(self::user('carol', 'carol-subject'), $demo));
    }

    #[Test]
    public function aRevocationIsWrittenOnSave(): void
    {
        $consents = self::consents();
        $user = self::user();
        $client = self::client();
        $consent = new Consent(Uuid::v7(), $user, $client, [new Scope('openid')], self::now());
        $consents->save($consent);
        $consent->revoke(self::now()->modify('+1 hour'));
        $consents->save($consent);
        self::reload();

        static::assertNull($consents->findActive($user, $client));
        static::assertEquals(self::now()->modify('+1 hour'), self::entityManager()->find(Consent::class, $consent->id)?->revokedAt);
    }

    private static function consents(): ConsentRepositoryInterface
    {
        return self::service('test.heidi.consents', ConsentRepositoryInterface::class);
    }
}
