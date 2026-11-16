<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Command;

use function array_map;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Port\GroupMembershipRepositoryInterface;
use Beffroi\Core\Port\GroupsOfAPersonInterface;
use PHPUnit\Framework\Attributes\Test;
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
