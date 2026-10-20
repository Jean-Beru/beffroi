<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\SingleLogout\SignOutRequest;
use Beffroi\Saml\Port\LogoutRequestReceiverInterface;

/**
 * A receiver that accepts whatever arrives as the logout request a test gives it, over either binding, and counts the
 * messages it was handed, each of which the receiver of the bundle would have remembered.
 */
final class GivenSignOutRequests implements LogoutRequestReceiverInterface
{
    public private(set) int $received = 0;

    public function __construct(
        private readonly SignOutRequest $request,
    ) {
    }

    public function redirect(Tenant $tenant, string $queryString): SignOutRequest
    {
        ++$this->received;

        return $this->request;
    }

    public function post(Tenant $tenant, array $fields): SignOutRequest
    {
        ++$this->received;

        return $this->request;
    }
}
