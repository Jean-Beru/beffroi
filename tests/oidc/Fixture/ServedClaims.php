<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use function array_map;
use Heidi\Core\Domain\Identity\User;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Port\ClaimsProviderInterface;

/**
 * A claims provider that serves exactly what a test names, to say what the document announces of a
 * deployment whose integration lists this and not the standard set.
 */
final readonly class ServedClaims implements ClaimsProviderInterface
{
    /**
     * @param list<string> $scopes
     * @param list<string> $claims
     */
    private function __construct(
        private array $scopes,
        private array $claims,
    ) {
    }

    /**
     * @param list<string> $scopes
     * @param list<string> $claims
     */
    public static function of(array $scopes, array $claims): self
    {
        return new self($scopes, $claims);
    }

    public function claims(User $user, ?Scopes $scopes, array $requested): array
    {
        return [];
    }

    public function supportedScopes(): array
    {
        return array_map(static fn (string $scope): Scope => new Scope($scope), $this->scopes);
    }

    public function supportedClaims(): array
    {
        return $this->claims;
    }
}
