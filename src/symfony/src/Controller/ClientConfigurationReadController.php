<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\ClientRegistrationAnswer;
use Heidi\Oidc\Application\Client\Registration\ClientConfigurationReader;
use Heidi\Oidc\Exception\UnauthorizedBearerRequestException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * A client reads itself at its own configuration endpoint (RFC 7592 §2.1), GET only. The path is the one
 * the "registration_client_uri" of its registration response named, and the request carries the
 * registration access token that answer handed it; anything else is the 401 of §2.3.
 */
#[AsController]
final readonly class ClientConfigurationReadController
{
    public const string ROUTE = 'heidi_protocol_client_configuration_read';

    /**
     * The client the URI answers for, which is the one the token must have been drawn for.
     */
    public const string CLIENT_ID = 'client_id';

    public const string PATH = '/register/{' . self::CLIENT_ID . '}';

    public function __construct(
        private TenantProvider $tenants,
        private ClientConfigurationReader $reader,
    ) {
    }

    #[Route(self::PATH, name: self::ROUTE, methods: ['GET'])]
    public function __invoke(Request $request, string $client_id): Response
    {
        try {
            $response = $this->reader->read($this->tenants->provide(), $client_id, $request->headers->get('Authorization'));
        } catch (UnauthorizedBearerRequestException $exception) {
            return ClientRegistrationAnswer::challenge($exception);
        }

        return ClientRegistrationAnswer::information($response);
    }
}
