<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Command;

use function array_map;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Port\GroupMembershipRepositoryInterface;
use Beffroi\Core\Port\GroupsOfAPersonInterface;
use Beffroi\Core\Domain\Event\GroupMembershipAdded;
use Beffroi\Core\Domain\Event\GroupMembershipRemoved;
use PHPUnit\Framework\Attributes\Test;
use function count;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0002: the members the tenant holds itself in its groups, given and taken back from the console, which is
 * what makes somebody an administrator of the tenant when the group is one its deployment names (decision 0038).
 */
final class GroupMembersTest extends ConsoleTestCase
{
    #[Test]
    public function aUserIsMadeAMemberOfAGroupFromTheConsole(): void
    {
        // Given
        $user = self::user();
        self::console('beffroi:group:create', [
            'name' => 'administrators',
        ]);

        // When
        $tester = self::console('beffroi:group:add-member', [
            'group' => 'administrators',
            'username' => 'alice',
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame([['administrators', GroupSource::Local]], array_map(
            static fn (GroupMembership $membership): array => [$membership->group->name, $membership->source],
            self::service('test.beffroi.groups_of_a_person', GroupsOfAPersonInterface::class)->of($user),
        ));
    }

    /**
     * Decision 0038: a membership can make an administrator, so it is an act of the person, whose provenance names the
     * operator of the console.
     */
    #[Test]
    public function eachMembershipGivenOrTakenBackFromTheConsoleIsAnActOfThePerson(): void
    {
        // Given
        self::user();
        self::console('beffroi:group:create', [
            'name' => 'administrators',
        ]);

        // When
        self::console('beffroi:group:add-member', [
            'group' => 'administrators',
            'username' => 'alice',
        ]);
        self::console('beffroi:group:remove-member', [
            'group' => 'administrators',
            'username' => 'alice',
        ]);

        // Then
        static::assertSame([1, 1], [count(self::events(GroupMembershipAdded::class)), count(self::events(GroupMembershipRemoved::class))]);
    }

    #[Test]
    public function aGroupTheTenantDoesNotHaveIsSaidToBeMissing(): void
    {
        // Given
        self::user();

        // When
        $tester = self::console('beffroi:group:add-member', [
            'group' => 'administrators',
            'username' => 'alice',
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('There is no group named "administrators" in the tenant', self::flattened($tester));
    }

    #[Test]
    public function aMembershipTheTenantHoldsIsTakenBackFromTheConsole(): void
    {
        // Given
        $user = self::user();
        self::console('beffroi:group:create', [
            'name' => 'administrators',
        ]);
        self::console('beffroi:group:add-member', [
            'group' => 'administrators',
            'username' => 'alice',
        ]);

        // When
        $tester = self::console('beffroi:group:remove-member', [
            'group' => 'administrators',
            'username' => 'alice',
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame([], self::service('test.beffroi.groups_of_a_person', GroupsOfAPersonInterface::class)->of($user));
    }

    /**
     * The next assertion of the upstream provider would write it again.
     */
    #[Test]
    public function aMembershipAnUpstreamProviderGaveIsNotTakenBackFromTheConsole(): void
    {
        // Given
        $user = self::user();
        $group = new Group(Uuid::v7(), self::tenant(), 'administrators', GroupSource::Local, self::now());
        self::entityManager()->persist($group);
        self::entityManager()->flush();
        self::service('test.beffroi.group_memberships', GroupMembershipRepositoryInterface::class)
            ->save(new GroupMembership(Uuid::v7(), $group, $user, GroupSource::UpstreamClaims, self::now()));

        // When
        $tester = self::console('beffroi:group:remove-member', [
            'group' => 'administrators',
            'username' => 'alice',
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('by a directory, which alone takes the membership back', self::flattened($tester));
    }
}
