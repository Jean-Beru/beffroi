<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Core\Application\Administration\Administrators;
use Beffroi\Core\Bridge\Configuration\ConfigurationAdministratorGroups;
use Beffroi\Core\Bridge\InMemory\InMemoryGroupMembershipRepository;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\GroupsOfAPersonInterface;
use Beffroi\Oidc\Application\Administration\AdministrationAudience;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationAdministrationResource;

/**
 * The administration API of a tenant as a deployment declares it (decision 0038): none, which reserves nothing, as
 * every test that is not about it has; or one, reserved to the members of one group.
 */
final readonly class Administrations
{
    public const string RESOURCE = 'https://admin.op.example';

    public const string GROUP = 'administrators';

    public static function none(): AdministrationAudience
    {
        return new AdministrationAudience(
            new ConfigurationAdministrationResource('none'),
            new Administrators(new ConfigurationAdministratorGroups('none'), new InMemoryGroupMembershipRepository()),
        );
    }

    /**
     * The resource, RESOURCE unless another is named, reserved to the members of GROUP in that tenant, whose
     * memberships are the ones given.
     */
    public static function of(Tenant $tenant, GroupsOfAPersonInterface $memberships, string $resource = self::RESOURCE): AdministrationAudience
    {
        return new AdministrationAudience(
            new ConfigurationAdministrationResource($tenant->slug, $resource),
            new Administrators(new ConfigurationAdministratorGroups($tenant->slug, [self::GROUP]), $memberships),
        );
    }
}
