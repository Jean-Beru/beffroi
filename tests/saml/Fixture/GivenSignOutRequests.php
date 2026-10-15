<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\SingleLogout\SignOutRequest;
use Beffroi\Saml\Port\LogoutRequestReceiverInterface;

/**
 * A receiver that accepts whatever arrives as the logout request a test gives it, over either binding.
 */
final readonly class GivenSignOutRequests implements LogoutRequestReceiverInterface
{
    public function __construct(
        private SignOutRequest $request,
    ) {
    }

    public function redirect(Tenant $tenant, string $queryString): SignOutRequest
    {
        return $this->request;
    }

    public function post(Tenant $tenant, array $fields): SignOutRequest
    {
        return $this->request;
    }
}
