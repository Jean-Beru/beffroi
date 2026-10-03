<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Doctrine;

use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Domain\Identity\LinkedIdentity;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Port\ActsOfAPersonInterface;
use Beffroi\Core\Port\GroupsOfAPersonInterface;
use Beffroi\Core\Port\JournalInterface;
use Beffroi\Core\Port\LinkedIdentitiesOfAPersonInterface;
use Beffroi\Core\Port\LinkedIdentityRepositoryInterface;
use function array_map;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use Symfony\Component\Uid\Uuid;

/**
 * Issue #453: the three readings the archive of a person needs of this database, which no page of the
 * account asked for before it. What the chapters do with them is tested on the chapters; what is here is
 * that the store answers the right rows, in the right order, for the right person.
 */
final class WhatAnArchiveReadsTest extends DatabaseTestCase
{
    /**
     * The whole journal of a person and not a few names: which acts answer a question is the question's,
     * and the archive asks for all of them.
     */
    #[Test]
    public function theWholeJournalOfAPersonIsReadWhateverTheActIsCalled(): void
    {
        // Given
        $user = self::user();
        self::record($user, ['first.act', 'second.act', UserAuthenticated::NAME]);

        // When
        $acts = self::acts()->everyActOf($user, 10);

        // Then
        static::assertSame(['first.act', 'second.act', UserAuthenticated::NAME], array_map(static fn (JournalEntry $act): string => $act->act, $acts));
    }

    /**
     * Read in pages past the last act read, which is what the identifier being a UUIDv7 is for: a page is
     * a lookup and never a sort of the whole journal.
     */
    #[Test]
    public function theJournalIsReadInPagesPastTheLastActRead(): void
    {
        // Given
        $user = self::user();
        self::record($user, ['first.act', 'second.act', 'third.act']);
        $first = self::acts()->everyActOf($user, 2);

        // When
        $next = self::acts()->everyActOf($user, 2, $first[1]->id);

        // Then
        static::assertSame(['first.act', 'second.act'], array_map(static fn (JournalEntry $act): string => $act->act, $first));
        static::assertSame(['third.act'], array_map(static fn (JournalEntry $act): string => $act->act, $next));
    }

    #[Test]
    public function theJournalOfAnotherPersonIsNotRead(): void
    {
        // Given
        $alice = self::user();
        $bob = self::user('bob', 'bob-subject');
        self::record($bob, [UserAuthenticated::NAME]);

        // When / Then
        static::assertSame([], self::acts()->everyActOf($alice, 10));
    }

    #[Test]
    public function theGroupsOfAPersonAreReadByTheNameOfTheGroup(): void
    {
        // Given
        $user = self::user();
        self::membership($user, 'operators', GroupSource::Scim);
        self::membership($user, 'admins', GroupSource::UpstreamClaims);
        self::reload();

        // When
        $memberships = self::theGroups()->of(self::reread($user));

        // Then
        static::assertSame(['admins', 'operators'], array_map(static fn (GroupMembership $m): string => $m->group->name, $memberships));
        static::assertSame(GroupSource::UpstreamClaims, $memberships[0]->source);
    }

    #[Test]
    public function theGroupsOfAnotherPersonAreNotRead(): void
    {
        // Given
        $alice = self::user();
        $bob = self::user('bob', 'bob-subject');
        self::membership($bob, 'admins', GroupSource::Local);
        self::reload();

        // When / Then
        static::assertSame([], self::theGroups()->of(self::reread($alice)));
    }

    #[Test]
    public function theIdentitiesOfAPersonAreReadMostRecentlyLinkedFirst(): void
    {
        // Given
        $user = self::user();
        self::identity($user, 'login.first.example', self::now());
        self::identity($user, 'login.second.example', self::now()->modify('+1 day'));
        self::reload();

        // When
        $identities = self::identities()->of(self::reread($user));

        // Then
        static::assertSame(
            ['login.second.example', 'login.first.example'],
            array_map(static fn (LinkedIdentity $identity): string => $identity->provider, $identities),
        );
    }

    #[Test]
    public function theIdentitiesOfAnotherPersonAreNotRead(): void
    {
        // Given
        $alice = self::user();
        $bob = self::user('bob', 'bob-subject');
        self::identity($bob, 'login.first.example', self::now());
        self::reload();

        // When / Then
        static::assertSame([], self::identities()->of(self::reread($alice)));
    }

    /**
     * @param list<string> $names
     */
    private static function record(User $user, array $names): void
    {
        $journal = self::service('test.beffroi.journal', JournalInterface::class);
        foreach ($names as $name) {
            $journal->record(new JournalEntry(Uuid::v7(), $user->tenant, $name, self::now(), self::context(), $user->subject));
        }
        self::reload();
    }

    private static function membership(User $user, string $name, GroupSource $source): void
    {
        $group = new Group(Uuid::v7(), self::tenant(), $name, $source, self::now());
        self::entityManager()->persist($group);
        self::entityManager()->persist(new GroupMembership(Uuid::v7(), $group, $user, $source, self::now()));
        self::entityManager()->flush();
    }

    private static function identity(User $user, string $provider, DateTimeImmutable $linkedAt): void
    {
        self::service('test.beffroi.linked_identities', LinkedIdentityRepositoryInterface::class)
            ->save(new LinkedIdentity(Uuid::v7(), $user, $provider, sprintf('%s-at-%s', $user->username, $provider), [], $linkedAt, $linkedAt));
    }

    private static function reread(User $user): User
    {
        $reread = self::entityManager()->find(User::class, $user->id);
        static::assertInstanceOf(User::class, $reread);

        return $reread;
    }

    private static function acts(): ActsOfAPersonInterface
    {
        return self::service('test.beffroi.acts', ActsOfAPersonInterface::class);
    }

    private static function theGroups(): GroupsOfAPersonInterface
    {
        return self::service('test.beffroi.groups_of_a_person', GroupsOfAPersonInterface::class);
    }

    private static function identities(): LinkedIdentitiesOfAPersonInterface
    {
        return self::service('test.beffroi.linked_identities', LinkedIdentitiesOfAPersonInterface::class);
    }
}
