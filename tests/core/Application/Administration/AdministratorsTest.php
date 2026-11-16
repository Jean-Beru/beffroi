<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Administration;

use Beffroi\Core\Application\Administration\Administrators;
use Beffroi\Core\Bridge\Configuration\ConfigurationAdministratorGroups;
use Beffroi\Core\Bridge\InMemory\InMemoryGroupMembershipRepository;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0038: an administrator of a tenant is a member of one of the groups its deployment names, read from the
 * groups of the person (decision 0002) when it is asked.
 */
final class AdministratorsTest extends TestCase
{
    private Tenant $tenant;

    private User $user;

    private InMemoryGroupMembershipRepository $memberships;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->user = Fixtures::user($this->tenant);
        $this->memberships = new InMemoryGroupMembershipRepository();
    }

    /**
     * A directory holds the membership as well as the tenant does.
     */
    #[Test]
    #[DataProvider('provideSources')]
    public function aMemberOfANamedGroupAdministersTheTenant(GroupSource $source): void
    {
        // Given
        $this->member('administrators', $source);

        // When
        $administers = $this->administrators(['operators', 'administrators'])->include($this->user);

        // Then
        static::assertTrue($administers);
    }

    /**
     * @return iterable<string, array{GroupSource}>
     */
    public static function provideSources(): iterable
    {
        yield 'held by the tenant' => [GroupSource::Local];
        yield 'held by an upstream provider' => [GroupSource::UpstreamClaims];
        yield 'held by SCIM' => [GroupSource::Scim];
    }

    #[Test]
    public function aMemberOfAnotherGroupDoesNotAdministerTheTenant(): void
    {
        // Given
        $this->member('accountants', GroupSource::Local);

        // When
        $administers = $this->administrators(['administrators'])->include($this->user);

        // Then
        static::assertFalse($administers);
    }

    #[Test]
    public function nobodyAdministersATenantWhoseDeploymentNamesNoGroup(): void
    {
        // Given
        $this->member('administrators', GroupSource::Local);

        // When
        $administers = $this->administrators([])->include($this->user);

        // Then
        static::assertFalse($administers);
    }

    #[Test]
    public function aPersonTakenOutOfTheGroupStopsAdministeringTheTenantAtOnce(): void
    {
        // Given
        $membership = $this->member('administrators', GroupSource::Local);
        $administrators = $this->administrators(['administrators']);
        $this->memberships->remove($membership);

        // When
        $administers = $administrators->include($this->user);

        // Then
        static::assertFalse($administers);
    }

    /**
     * @param list<string> $groups
     */
    private function administrators(array $groups): Administrators
    {
        return new Administrators(new ConfigurationAdministratorGroups($this->tenant->slug, $groups), $this->memberships);
    }

    private function member(string $group, GroupSource $source): GroupMembership
    {
        $membership = new GroupMembership(
            Uuid::v7(),
            new Group(Uuid::v7(), $this->tenant, $group, $source, Fixtures::now()),
            $this->user,
            $source,
            Fixtures::now(),
        );
        $this->memberships->save($membership);

        return $membership;
    }
}
