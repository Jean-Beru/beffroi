<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Port\UnsignedRequestObjectsInterface;

/**
 * What the registered clients of a tenant make of "request_object_signing_alg" (OIDC Registration §2):
 * one of them registered "none", or every one of them signs its request objects.
 */
final readonly class RequestObjectSignings implements UnsignedRequestObjectsInterface
{
    private function __construct(
        private bool $unsigned,
    ) {
    }

    public static function oneClientSendsThemUnsigned(): self
    {
        return new self(true);
    }

    public static function everyClientSignsThem(): self
    {
        return new self(false);
    }

    public function acceptsUnsignedRequestObjects(Tenant $tenant): bool
    {
        return $this->unsigned;
    }
}
