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
 * OIDC Core §5.1
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
