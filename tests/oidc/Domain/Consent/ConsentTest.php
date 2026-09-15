<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Consent;

use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Consent\Consent;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class ConsentTest extends TestCase
{
    /**
     * Architecture §4.3: a consent binds a user and a client of the same tenant to a set of scopes, and
     * covers a request when every requested scope is in that set.
     */
    #[Test]
    public function itCoversARequestWhoseScopesWereAllGranted(): void
    {
        $user = Fixtures::user();
        $client = Clients::public($user->tenant);
        $consent = new Consent(Uuid::v7(), $user, $client, [new Scope('openid'), new Scope('profile'), new Scope('openid')], Fixtures::now());

        static::assertSame($user->tenant, $consent->tenant);
        static::assertSame($client->clientId, $consent->clientId);
        static::assertEquals([new Scope('openid'), new Scope('profile')], $consent->scopes);
        static::assertTrue($consent->covers([new Scope('openid')]));
        static::assertTrue($consent->covers([new Scope('profile'), new Scope('openid')]));
        static::assertTrue($consent->covers([]));
        static::assertFalse($consent->covers([new Scope('openid'), new Scope('email')]));
        static::assertTrue($consent->hasScope(new Scope('profile')));
        static::assertFalse($consent->hasScope(new Scope('email')));
        static::assertTrue($consent->isActive());
        static::assertNull($consent->revokedAt);
    }

    #[Test]
    public function itIsForItsUserAndItsClientOnly(): void
    {
        $user = Fixtures::user();
        $client = Clients::public($user->tenant);
        $consent = new Consent(Uuid::v7(), $user, $client, [new Scope('openid')], Fixtures::now());

        static::assertTrue($consent->isFor($user, $client));
        static::assertTrue($consent->isFor($user, Clients::public($user->tenant)));
        static::assertFalse($consent->isFor(Fixtures::user($user->tenant, 'bob', 'bob-subject'), $client));
        static::assertFalse($consent->isFor($user, Clients::public($user->tenant, 'another-app')));
    }

    /**
     * The first revocation wins.
     */
    #[Test]
    public function itIsRevokedOnce(): void
    {
        $user = Fixtures::user();
        $consent = new Consent(Uuid::v7(), $user, Clients::public($user->tenant), [new Scope('openid')], Fixtures::now());

        $consent->revoke(Fixtures::now()->modify('+1 day'));
        $consent->revoke(Fixtures::now()->modify('+2 days'));

        static::assertFalse($consent->isActive());
        static::assertEquals(Fixtures::now()->modify('+1 day'), $consent->revokedAt);
    }

    #[Test]
    public function itRefusesAClientOfAnotherTenant(): void
    {
        $user = Fixtures::user();

        $this->expectException(InvalidArgumentException::class);
        new Consent(Uuid::v7(), $user, Clients::public(Fixtures::tenant('other', 'https://id.other.example')), [new Scope('openid')], Fixtures::now());
    }

    #[Test]
    public function itRefusesAnEmptyScopeSet(): void
    {
        $user = Fixtures::user();

        $this->expectException(InvalidArgumentException::class);
        new Consent(Uuid::v7(), $user, Clients::public($user->tenant), [], Fixtures::now());
    }
}
