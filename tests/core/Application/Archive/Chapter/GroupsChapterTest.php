<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Archive\Chapter;

use Beffroi\Core\Application\Archive\Chapter\GroupsChapter;
use Beffroi\Core\Bridge\InMemory\InMemoryGroupMembershipRepository;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function array_column;
use Symfony\Component\Uid\Uuid;

/**
 * Issue #453: the groups a person belongs to, in the archive they ask for. The source is on the line
 * because it is the answer to what a person does about it (decision 0002): a membership a directory
 * declared is not one this provider decided, and a person reading their file learns which door to knock on.
 */
final class GroupsChapterTest extends TestCase
{
    #[Test]
    public function aMembershipIsOnTheNameOfTheGroupItsSourceAndItsDate(): void
    {
        // Given
        $user = Fixtures::user();
        $memberships = new InMemoryGroupMembershipRepository();
        $memberships->save(self::membership($user, 'admins', GroupSource::Scim));

        // When
        $lines = new GroupsChapter($memberships)->of($user);

        // Then
        static::assertSame(
            [
                [
                    'name' => 'admins',
                    'source' => 'scim',
                    'added_at' => Fixtures::now()->format('c'),
                ],
            ],
            $lines,
        );
    }

    /**
     * The source of the membership and not the source of the group: a group a directory owns may hold
     * somebody a hand added, and what a person asks about is their own membership.
     */
    #[Test]
    public function theSourceIsTheOneOfTheMembership(): void
    {
        // Given
        $user = Fixtures::user();
        $memberships = new InMemoryGroupMembershipRepository();
        $group = new Group(Uuid::v7(), $user->tenant, 'admins', GroupSource::Scim, Fixtures::now());
        $memberships->save(new GroupMembership(Uuid::v7(), $group, $user, GroupSource::Local, Fixtures::now()));

        // When
        $lines = new GroupsChapter($memberships)->of($user);

        // Then
        static::assertSame('local', $lines[0]['source']);
    }

    /**
     * By the name of the group, so that two files of the same person read alike.
     */
    #[Test]
    public function theGroupsAreInTheOrderOfTheirNames(): void
    {
        // Given
        $user = Fixtures::user();
        $memberships = new InMemoryGroupMembershipRepository();
        $memberships->save(self::membership($user, 'operators', GroupSource::Scim));
        $memberships->save(self::membership($user, 'admins', GroupSource::Scim));

        // When
        $lines = new GroupsChapter($memberships)->of($user);

        // Then
        static::assertSame(['admins', 'operators'], array_column($lines, 'name'));
    }

    #[Test]
    public function theGroupsOfAnotherPersonAreNotInTheChapter(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $ada = Fixtures::user($tenant, 'ada', 'ada-subject');
        $grace = Fixtures::user($tenant, 'grace', 'grace-subject');
        $memberships = new InMemoryGroupMembershipRepository();
        $memberships->save(self::membership($grace, 'admins', GroupSource::Local));

        // When / Then
        static::assertSame([], new GroupsChapter($memberships)->of($ada));
    }

    #[Test]
    public function aPersonInNoGroupHasAnEmptyChapter(): void
    {
        // When / Then
        static::assertSame([], new GroupsChapter(new InMemoryGroupMembershipRepository())->of(Fixtures::user()));
    }

    private static function membership(User $user, string $name, GroupSource $source): GroupMembership
    {
        $group = new Group(Uuid::v7(), $user->tenant, $name, $source, Fixtures::now());

        return new GroupMembership(Uuid::v7(), $group, $user, $source, Fixtures::now());
    }
}
