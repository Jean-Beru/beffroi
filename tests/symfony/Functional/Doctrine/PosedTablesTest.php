<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine;

use Heidi\Core\Domain\Group\Group;
use Heidi\Core\Domain\Group\GroupMembership;
use Heidi\Core\Domain\Group\GroupSource;
use Heidi\Core\Domain\Identity\LinkedIdentity;
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
        $entityManager = self::entityManager();
        $user = self::user();
        $identity = new LinkedIdentity(Uuid::v7(), $user, 'google', '1234567890', [
            'email' => 'alice@example.com',
            'email_verified' => true,
        ], self::now(), self::now());
        $entityManager->persist($identity);
        $entityManager->flush();
        self::reload();

        $found = self::entityManager()->find(LinkedIdentity::class, $identity->id) ?? static::fail('The linked identity was not stored.');

        static::assertTrue($found->user->id->equals($user->id));
        static::assertTrue($found->tenant->id->equals(self::tenant()->id));
        static::assertSame('google', $found->provider);
        static::assertSame('1234567890', $found->subject);
        static::assertSame([
            'email' => 'alice@example.com',
            'email_verified' => true,
        ], $found->claims);
        static::assertEquals(self::now(), $found->linkedAt);
        static::assertEquals(self::now(), $found->lastSeenAt);
    }

    #[Test]
    public function aGroupAndAMembershipRoundTrip(): void
    {
        $entityManager = self::entityManager();
        $user = self::user();
        $group = new Group(Uuid::v7(), self::tenant(), 'admins', GroupSource::Scim, self::now());
        $membership = new GroupMembership(Uuid::v7(), $group, $user, GroupSource::UpstreamClaims, self::now());
        $entityManager->persist($group);
        $entityManager->persist($membership);
        $entityManager->flush();
        self::reload();

        $foundGroup = self::entityManager()->find(Group::class, $group->id) ?? static::fail('The group was not stored.');
        $foundMembership = self::entityManager()->find(GroupMembership::class, $membership->id) ?? static::fail('The membership was not stored.');

        static::assertSame('admins', $foundGroup->name);
        static::assertSame(GroupSource::Scim, $foundGroup->source);
        static::assertTrue($foundGroup->tenant->id->equals(self::tenant()->id));
        static::assertSame($foundGroup, $foundMembership->group);
        static::assertTrue($foundMembership->user->id->equals($user->id));
        static::assertTrue($foundMembership->tenant->id->equals(self::tenant()->id));
        static::assertSame(GroupSource::UpstreamClaims, $foundMembership->source);
        static::assertEquals(self::now(), $foundMembership->addedAt);
    }
}
