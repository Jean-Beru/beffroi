<?php

declare(strict_types=1);

namespace App\Controller;

use App\Doctrine\TenantProvider;
use App\Http\ClientRegistrationAnswer;
use App\Http\RequestContextFactory;
use Beffroi\Oidc\Application\Client\Registration\ClientConfigurationRemoval;
use Beffroi\Oidc\Exception\UnauthorizedBearerRequestException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * A client deletes itself (RFC 7592 §2.3), DELETE only: a 204 and nothing to answer, the client being
 * gone. The token that read it reads nothing afterwards, which is what a client that comes back sees.
 */
#[AsController]
final readonly class ClientConfigurationDeleteController
{
    public const string ROUTE = 'beffroi_protocol_client_configuration_delete';

    public function __construct(
        private TenantProvider $tenants,
        private ClientConfigurationRemoval $removal,
        private RequestContextFactory $contexts,
    ) {
    }

    #[Route(ClientConfigurationReadController::PATH, name: self::ROUTE, methods: ['DELETE'])]
    public function __invoke(Request $request, string $client_id): Response
    {
        try {
            $this->removal->remove(
                $this->tenants->provide(),
                $client_id,
                $request->headers->get('Authorization'),
                $this->contexts->fromRequest($request),
            );
        } catch (UnauthorizedBearerRequestException $exception) {
            return ClientRegistrationAnswer::challenge($exception);
        }

        return ClientRegistrationAnswer::gone();
    }
}
