<?php

declare(strict_types=1);

namespace App\Fido\Conformance;

use Beffroi\Core\Application\Identity\UserProvisioner;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\UserRepositoryInterface;

/**
 * The users the conformance tools name: created on their first ceremony with the display name given,
 * which the product never does (no self-service sign-up, the spike README), found back afterwards. They
 * are users of the tenant like any other, without a password.
 */
final readonly class ConformanceUsers
{
    public function __construct(
        private UserRepositoryInterface $users,
        private UserProvisioner $provisioner,
    ) {
    }

    public function findOrCreate(Tenant $tenant, string $username, string $displayName): User
    {
        $user = $this->users->findByUsername($tenant, $username);
        if ($user !== null) {
            return $user;
        }
        $user = $this->provisioner->create($tenant, $username);

        return $this->provisioner->setProfile($user, new Profile(name: $displayName));
    }

    public function find(Tenant $tenant, string $username): ?User
    {
        return $this->users->findByUsername($tenant, $username);
    }
}
