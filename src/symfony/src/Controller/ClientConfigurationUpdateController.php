<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\ClientRegistrationAnswer;
use Heidi\Oidc\Application\Client\Registration\ClientConfigurationReplacement;
use Heidi\Oidc\Domain\Client\Registration\RegistrationRequest;
use Heidi\Oidc\Exception\UnauthorizedBearerRequestException;
use Heidi\Oidc\Exception\UnreadableClientMetadataException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * A client replaces its own registration (RFC 7592 §2.2), PUT only: the whole registration in, what the
 * provider now holds of it out. A member the request leaves out is a member the client no longer
 * registers, and a request that would reach what a registration could not is refused exactly as that
 * registration would have been.
 */
#[AsController]
final readonly class ClientConfigurationUpdateController
{
    public const string ROUTE = 'heidi_protocol_client_configuration_update';

    public function __construct(
        private TenantProvider $tenants,
        private ClientConfigurationReplacement $replacement,
    ) {
    }

    #[Route(ClientConfigurationReadController::PATH, name: self::ROUTE, methods: ['PUT'])]
    public function __invoke(Request $request, string $client_id): Response
    {
        try {
            $response = $this->replacement->replace(
                $this->tenants->provide(),
                $client_id,
                new RegistrationRequest(ClientRegistrationAnswer::members($request), $request->headers->get('Authorization')),
            );
        } catch (UnauthorizedBearerRequestException $exception) {
            return ClientRegistrationAnswer::challenge($exception);
        } catch (UnreadableClientMetadataException $exception) {
            return ClientRegistrationAnswer::refusal($exception);
        }

        return ClientRegistrationAnswer::information($response);
    }
}
