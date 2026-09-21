<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Port\PushedAuthorizationRequirementInterface;

/**
 * What the registered clients of a tenant make of RFC 9126 §5: every one of them pushes its
 * authorization requests, or at least one of them does not.
 */
final readonly class PushedRequests implements PushedAuthorizationRequirementInterface
{
    private function __construct(
        private bool $required,
    ) {
    }

    public static function requiredOfEveryClient(): self
    {
        return new self(true);
    }

    public static function requiredOfNobody(): self
    {
        return new self(false);
    }

    public function requiresPushedAuthorizationRequests(Tenant $tenant): bool
    {
        return $this->required;
    }
}
