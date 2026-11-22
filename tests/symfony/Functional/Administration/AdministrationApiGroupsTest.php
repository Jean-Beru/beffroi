<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Administration;

use function array_map;
use function is_array;
use Beffroi\Core\Domain\Event\GroupCreated;
use Beffroi\Core\Domain\Event\GroupMembershipAdded;
use Beffroi\Core\Domain\Event\GroupMembershipRemoved;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\GroupMembershipRepositoryInterface;
use Beffroi\Core\Port\GroupRepositoryInterface;
use Beffroi\Core\Port\GroupsOfAPersonInterface;
use Beffroi\Oidc\Domain\Event\MembershipReadByAnAdministrator;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use Symfony\Component\Clock\Clock;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0038: an administrator lists the groups of the tenant, reads their members, creates a group and gives or
 * takes back a membership, through the administration API on the use cases of the commands of the console.
 */
final class AdministrationApiGroupsTest extends AdministrationTestCase
{
    #[Test]
    public function theGroupsAreListedWithHowManyMembersEachHoldsAndWhetherTheyAdminister(): void
    {
        // Given
        $auditors = self::group('auditors');
        self::member($auditors, self::user('bob', 'bob-subject'));
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api('/groups', $token);

        // Then
        static::assertSame(
            [
                ['administrators', 1, true],
                ['auditors',       1, false],
            ],
            array_map(
                static fn (array $group): array => [$group['name'] ?? null, $group['members'] ?? null, $group['administers'] ?? null],
                self::listed($response, 'groups'),
            ),
        );
    }

    #[Test]
    public function listingTheGroupsDeliversNobodyAndWritesNoAct(): void
    {
        // Given
        self::member(self::group('auditors'), self::user('bob', 'bob-subject'));
        $token = $this->administratorToken(self::user('alice'));

        // When
        $this->api('/groups', $token);

        // Then
        static::assertSame([], self::authored(MembershipReadByAnAdministrator::NAME));
    }

    /**
     * Decision 0022
     */
    #[Test]
    public function eachMemberReadIsAnActOfTheirsThatNamesTheAdministrator(): void
    {
        // Given
        $auditors = self::group('auditors');
        self::member($auditors, self::user('bob', 'bob-subject'));
        self::member($auditors, self::user('carol', 'carol-subject'));
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api(sprintf('/groups/%s/members', $auditors->id->toRfc4122()), $token);

        // Then
        static::assertSame(
            [
                ['bob', 'carol'],
                [
                    ['bob-subject',   'alice-subject'],
                    ['carol-subject', 'alice-subject'],
                ],
            ],
            [
                array_map(
                    static fn (array $member): mixed => is_array($member['person'] ?? null) ? $member['person']['username'] ?? null : null,
                    self::listed($response, 'members'),
                ),
                self::authored(MembershipReadByAnAdministrator::NAME),
            ],
        );
    }

    #[Test]
    public function anAdministratorCreatesAGroupAndTheActNamesThem(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api('/groups', $token, method: 'POST', content: '{"name": "auditors"}');

        // Then
        static::assertSame(
            [Response::HTTP_CREATED, 'auditors', 0, [[null, 'alice-subject']]],
            [$response->getStatusCode(), ...self::members($response, ['name', 'members']), self::authored(GroupCreated::NAME)],
        );
    }

    #[Test]
    public function aNameTheTenantHoldsAlreadyIsAConflict(): void
    {
        // Given
        self::group('auditors');
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api('/groups', $token, method: 'POST', content: '{"name": "auditors"}');

        // Then
        static::assertSame([Response::HTTP_CONFLICT, 'conflict'], [$response->getStatusCode(), self::members($response, ['error'])[0]]);
    }

    #[Test]
    public function anAdministratorAddsAMemberAndTheActOfThePersonNamesThem(): void
    {
        // Given
        $auditors = self::group('auditors');
        $bob = self::user('bob', 'bob-subject');
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api(self::membersPath($auditors), $token, method: 'POST', content: '{"username": "bob"}');

        // Then
        static::assertSame(
            [Response::HTTP_CREATED, ['auditors'], [['bob-subject', 'alice-subject']]],
            [$response->getStatusCode(), self::groupsOf($bob), self::authored(GroupMembershipAdded::NAME)],
        );
    }

    #[Test]
    public function aMemberAddedAgainIsAConflict(): void
    {
        // Given
        $auditors = self::group('auditors');
        self::member($auditors, self::user('bob', 'bob-subject'));
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api(self::membersPath($auditors), $token, method: 'POST', content: '{"username": "bob"}');

        // Then
        static::assertSame([Response::HTTP_CONFLICT, []], [$response->getStatusCode(), self::authored(GroupMembershipAdded::NAME)]);
    }

    #[Test]
    public function aUsernameNobodyOfTheTenantHasIsNotFound(): void
    {
        // Given
        $auditors = self::group('auditors');
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api(self::membersPath($auditors), $token, method: 'POST', content: '{"username": "nobody"}');

        // Then
        static::assertSame([Response::HTTP_NOT_FOUND, 'not_found'], [$response->getStatusCode(), self::members($response, ['error'])[0]]);
    }

    #[Test]
    public function anAdministratorTakesAMemberOutAndTheActOfThePersonNamesThem(): void
    {
        // Given
        $auditors = self::group('auditors');
        $bob = self::user('bob', 'bob-subject');
        self::member($auditors, $bob);
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api(self::memberPath($auditors, $bob), $token, method: 'DELETE');

        // Then
        static::assertSame(
            [Response::HTTP_OK, [], [['bob-subject', 'alice-subject']]],
            [$response->getStatusCode(), self::groupsOf($bob), self::authored(GroupMembershipRemoved::NAME)],
        );
    }

    #[Test]
    public function aPersonWhoIsNoMemberIsNotFound(): void
    {
        // Given
        $auditors = self::group('auditors');
        $bob = self::user('bob', 'bob-subject');
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api(self::memberPath($auditors, $bob), $token, method: 'DELETE');

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $response->getStatusCode());
    }

    #[Test]
    public function anAdministratorDoesNotTakeThemselvesOutOfTheAdministrators(): void
    {
        // Given
        $alice = self::user('alice');
        $token = $this->administratorToken($alice);
        $administrators = self::groupsOfAPerson()->of($alice)[0]->group;

        // When
        $response = $this->api(self::memberPath($administrators, $alice), $token, method: 'DELETE');

        // Then
        static::assertSame(
            [Response::HTTP_CONFLICT, ['administrators'], []],
            [$response->getStatusCode(), self::groupsOf($alice), self::authored(GroupMembershipRemoved::NAME)],
        );
    }

    #[Test]
    public function aGroupOfAnotherIdentifierIsNotFound(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api(sprintf('/groups/%s/members', Uuid::v7()->toRfc4122()), $token);

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $response->getStatusCode());
    }

    private static function group(string $name): Group
    {
        $group = new Group(Uuid::v7(), self::tenant(), $name, GroupSource::Local, Clock::get()->now());
        self::service('test.beffroi.groups', GroupRepositoryInterface::class)->save($group);

        return $group;
    }

    private static function member(Group $group, User $user): void
    {
        self::service('test.beffroi.group_memberships', GroupMembershipRepositoryInterface::class)
            ->save(
                new GroupMembership(Uuid::v7(), $group, $user, GroupSource::Local, Clock::get()->now()),
            );
    }

    private static function membersPath(Group $group): string
    {
        return sprintf('/groups/%s/members', $group->id->toRfc4122());
    }

    private static function memberPath(Group $group, User $person): string
    {
        return sprintf('/groups/%s/members/%s', $group->id->toRfc4122(), $person->id->toRfc4122());
    }

    /**
     * @return list<string> the names of the groups of the person, as the store holds them now
     */
    private static function groupsOf(User $person): array
    {
        self::reload();

        return array_map(static fn (GroupMembership $membership): string => $membership->group->name, self::groupsOfAPerson()->of(self::personAgain($person)));
    }

    private static function groupsOfAPerson(): GroupsOfAPersonInterface
    {
        return self::service('test.beffroi.groups_of_a_person', GroupsOfAPersonInterface::class);
    }

    /**
     * @return list<array<array-key, mixed>>
     */
    private static function listed(Response $response, string $member): array
    {
        $listed = self::members($response, [$member])[0];
        static::assertIsArray($listed);

        $documents = [];
        foreach ($listed as $document) {
            static::assertIsArray($document);
            $documents[] = $document;
        }

        return $documents;
    }
}
