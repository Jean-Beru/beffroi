<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Command;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\UserRepositoryInterface;
use function sprintf;
use Symfony\Component\Console\Style\SymfonyStyle;
use function trim;

/**
 * The user a command names on its command line, of the tenant it works on. The name is read as the
 * shell handed it over, without the spaces a copied value carries, and a name nobody answers to is said
 * the same way by every command that takes one.
 */
final readonly class NamedUser
{
    public function __construct(
        private UserRepositoryInterface $users,
    ) {
    }

    /**
     * @return User|null null when the command was told there is no such user, and should fail
     */
    public function orTold(SymfonyStyle $io, Tenant $tenant, string $username): ?User
    {
        $name = trim($username);
        $user = $this->users->findByUsername($tenant, $name);
        if ($user === null) {
            $io->error(sprintf('There is no user named "%s" in the tenant "%s".', $name, $tenant->slug));

            return null;
        }

        return $user;
    }
}
