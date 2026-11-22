<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use Beffroi\Core\Application\Group\UpstreamMemberships;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupMapping;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\GroupMembershipRepositoryInterface;
use Beffroi\Core\Port\GroupsOfAPersonInterface;
use Beffroi\Core\Port\MembersOfAGroupInterface;
use PHPUnit\Framework\Attributes\Test;
use function array_map;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0002
 */
final class GroupMembershipsTest extends DatabaseTestCase
{
    #[Test]
    public function aMembershipSavedIsReadBack(): void
    {
        // Given
        $user = self::user();
        $admins = self::group('admins');

        // When
        self::memberships()->save(new GroupMembership(Uuid::v7(), $admins, $user, GroupSource::UpstreamClaims, self::now()));

        // Then
        self::reload();
        $memberships = self::groupsOf($user);
        static::assertCount(1, $memberships);
        static::assertSame('admins', $memberships[0]->group->name);
        static::assertSame(GroupSource::UpstreamClaims, $memberships[0]->source);
    }

    #[Test]
    public function aMembershipTakenBackLeavesTheTableAndTheGroupStays(): void
    {
        // Given
        $user = self::user();
        $admins = self::group('admins');
        self::memberships()->save(new GroupMembership(Uuid::v7(), $admins, $user, GroupSource::UpstreamClaims, self::now()));
        self::reload();
        $membership = self::groupsOf($user)[0];

        // When
        self::memberships()->remove($membership);

        // Then
        self::reload();
        static::assertSame([], self::groupsOf($user));
        static::assertNotNull(self::entityManager()->find(Group::class, $admins->id));
    }

    #[Test]
    public function aSignInReplacesTheUpstreamMembershipsInTheTable(): void
    {
        // Given
        $user = self::user();
        $admins = self::group('admins');
        $sales = self::group('sales');
        $staff = self::group('staff');
        self::memberships()->save(new GroupMembership(Uuid::v7(), $admins, $user, GroupSource::Local, self::now()));
        self::memberships()->save(new GroupMembership(Uuid::v7(), $sales, $user, GroupSource::UpstreamClaims, self::now()));
        $mapping = new GroupMapping([
            'sales-guid' => $sales,
            'staff-guid' => $staff,
        ]);

        // When
        self::service('test.beffroi.upstream_memberships', UpstreamMemberships::class)->replace($user, ['staff-guid'], $mapping);

        // Then
        self::reload();
        $sources = [];
        foreach (self::groupsOf($user) as $membership) {
            $sources[$membership->group->name] = $membership->source;
        }
        static::assertSame(
            [
                'admins' => GroupSource::Local,
                'staff' => GroupSource::UpstreamClaims,
            ],
            $sources,
        );
    }

    #[Test]
    public function theMembersOfAGroupAreListedInTheOrderTheyWereAdded(): void
    {
        // Given
        $admins = self::group('admins');
        $bob = self::user('bob', 'bob-subject');
        $alice = self::user('alice', 'alice-subject');
        self::memberships()->save(new GroupMembership(Uuid::v7(), $admins, $bob, GroupSource::Local, self::now()->modify('-1 hour')));
        self::memberships()->save(new GroupMembership(Uuid::v7(), $admins, $alice, GroupSource::Local, self::now()));
        self::reload();

        // When
        $members = self::members()->membersOf($admins);

        // Then
        static::assertSame(['bob', 'alice'], array_map(static fn (GroupMembership $membership): string => $membership->user->username, $members));
    }

    #[Test]
    public function theMembersOfAGroupAreCounted(): void
    {
        // Given
        $admins = self::group('admins');
        self::memberships()->save(new GroupMembership(Uuid::v7(), $admins, self::user('bob', 'bob-subject'), GroupSource::Local, self::now()));
        self::memberships()->save(new GroupMembership(Uuid::v7(), self::group('staff'), self::user('alice', 'alice-subject'), GroupSource::Local, self::now()));

        // When
        $count = self::members()->countMembersOf($admins);

        // Then
        static::assertSame(1, $count);
    }

    private static function members(): MembersOfAGroupInterface
    {
        return self::service('test.beffroi.members_of_a_group', MembersOfAGroupInterface::class);
    }

    private static function group(string $name): Group
    {
        $group = new Group(Uuid::v7(), self::tenant(), $name, GroupSource::Local, self::now());
        self::entityManager()->persist($group);
        self::entityManager()->flush();

        return $group;
    }

    private static function memberships(): GroupMembershipRepositoryInterface
    {
        return self::service('test.beffroi.group_memberships', GroupMembershipRepositoryInterface::class);
    }

    /**
     * @return list<GroupMembership>
     */
    private static function groupsOf(User $user): array
    {
        return self::service('test.beffroi.groups_of_a_person', GroupsOfAPersonInterface::class)->of($user);
    }
}
