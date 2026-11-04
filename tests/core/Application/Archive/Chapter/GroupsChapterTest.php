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
 * Decision 0002
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
