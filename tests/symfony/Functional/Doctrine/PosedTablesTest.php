<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Doctrine;

use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Domain\Identity\LinkedIdentity;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §8: the tables spike 1 poses without using them (linked identities, groups, memberships)
 * are mapped and round-trip through the entity manager, so that spike 3 finds them in place.
 */
final class PosedTablesTest extends DatabaseTestCase
{
    #[Test]
    public function aLinkedIdentityRoundTrips(): void
    {
        // Given
        $entityManager = self::entityManager();
        $user = self::user();
        $identity = new LinkedIdentity(
            Uuid::v7(),
            $user,
            'google',
            '1234567890',
            [
                'email' => 'alice@example.com',
                'email_verified' => true,
            ],
            self::now(),
            self::now(),
        );
        $entityManager->persist($identity);
        $entityManager->flush();
        self::reload();

        // When
        $found = self::entityManager()->find(LinkedIdentity::class, $identity->id) ?? static::fail('The linked identity was not stored.');

        // Then
        static::assertTrue($found->user->id->equals($user->id));
        static::assertTrue($found->tenant->id->equals(self::tenant()->id));
        static::assertSame('google', $found->provider);
        static::assertSame('1234567890', $found->subject);
        static::assertSame(
            [
                'email' => 'alice@example.com',
                'email_verified' => true,
            ],
            $found->claims,
        );
        static::assertEquals(self::now(), $found->linkedAt);
        static::assertEquals(self::now(), $found->lastSeenAt);
    }

    #[Test]
    public function aGroupRoundTrips(): void
    {
        // Given
        $group = new Group(Uuid::v7(), self::tenant(), 'admins', GroupSource::Scim, self::now());
        self::entityManager()->persist($group);
        self::entityManager()->flush();
        self::reload();

        // When
        $found = self::entityManager()->find(Group::class, $group->id) ?? static::fail('The group was not stored.');

        // Then
        static::assertSame('admins', $found->name);
        static::assertSame(GroupSource::Scim, $found->source);
        static::assertTrue($found->tenant->id->equals(self::tenant()->id));
    }

    #[Test]
    public function aMembershipRoundTripsWithItsGroupAndItsUser(): void
    {
        // Given
        $user = self::user();
        $group = new Group(Uuid::v7(), self::tenant(), 'admins', GroupSource::Scim, self::now());
        $membership = new GroupMembership(Uuid::v7(), $group, $user, GroupSource::UpstreamClaims, self::now());
        self::entityManager()->persist($group);
        self::entityManager()->persist($membership);
        self::entityManager()->flush();
        self::reload();

        // When
        $found = self::entityManager()->find(GroupMembership::class, $membership->id) ?? static::fail('The membership was not stored.');

        // Then
        static::assertTrue($found->group->id->equals($group->id));
        static::assertTrue($found->user->id->equals($user->id));
        static::assertTrue($found->tenant->id->equals(self::tenant()->id));
        static::assertSame(GroupSource::UpstreamClaims, $found->source);
        static::assertEquals(self::now(), $found->addedAt);
    }
}
