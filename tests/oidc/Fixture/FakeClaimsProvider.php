<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use function array_any;
use function array_map;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Port\ClaimsProviderInterface;

/**
 * A claims provider that serves exactly what a test names, to say what the document announces of a
 * deployment whose integration lists this and not the standard set, and what several of them wired
 * together answer.
 */
final readonly class FakeClaimsProvider implements ClaimsProviderInterface
{
    /**
     * @param list<string> $scopes
     * @param list<string> $claims
     * @param array<string, mixed> $values what this provider puts on a claim of a user, empty when the test only asks what it serves
     */
    private function __construct(
        private array $scopes,
        private array $claims,
        private array $values,
    ) {
    }

    /**
     * @param list<string> $scopes
     * @param list<string> $claims
     * @param array<string, mixed> $values
     */
    public static function of(array $scopes, array $claims, array $values = []): self
    {
        return new self($scopes, $claims, $values);
    }

    public function claims(User $user, ?Scopes $scopes, array $requested): array
    {
        return $this->values;
    }

    /**
     * Each claim it names stands for each scope it names.
     */
    public function claimsOf(Scopes $scopes): array
    {
        return array_any($this->scopes, static fn (string $scope): bool => $scopes->has(new Scope($scope))) ? $this->claims : [];
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
