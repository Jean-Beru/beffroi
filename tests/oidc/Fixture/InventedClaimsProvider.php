<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use function array_keys;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Port\ClaimsProviderInterface;
use function in_array;
use function sprintf;

/**
 * A claims provider nobody wrote a line of production code for (OIDC Core §5.1), which is what a
 * deployment adds when its own store holds something about a person that the standard claims do not say:
 * it names the scope it serves, it names the claim that scope stands for, and it answers for that claim
 * alone. The standard provider is wired beside it and neither knows of the other.
 */
final readonly class InventedClaimsProvider implements ClaimsProviderInterface
{
    public const string SCOPE = 'staff';

    public const string CLAIM = 'staff_number';

    public function claims(User $user, ?Scopes $scopes, array $requested): array
    {
        $due = $scopes?->has(new Scope(self::SCOPE)) === true || in_array(self::CLAIM, array_keys($requested), true);

        return $due ? [self::CLAIM => sprintf('EMP-%s', $user->username)] : [];
    }

    public function claimsOf(Scopes $scopes): array
    {
        return $scopes->has(new Scope(self::SCOPE)) ? [self::CLAIM] : [];
    }

    public function supportedScopes(): array
    {
        return [new Scope(self::SCOPE)];
    }

    public function supportedClaims(): array
    {
        return [self::CLAIM];
    }
}
