<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Port\PushedAuthorizationRequirementInterface;

/**
 * RFC 9126 §5
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
