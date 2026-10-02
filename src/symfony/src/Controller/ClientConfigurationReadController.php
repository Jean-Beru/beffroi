<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Http\ClientRegistrationAnswer;
use Beffroi\Oidc\Application\Client\Registration\ClientConfigurationReader;
use Beffroi\Oidc\Exception\UnauthorizedBearerRequestException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * A client reads itself at its own configuration endpoint (RFC 7592 §2.1), GET only. The path is the one
 * the "registration_client_uri" of its registration response named, and the request carries the
 * registration access token that answer handed it; anything else is the 401 of §2.3.
 *
 * §2 switches the operations of this endpoint on the HTTP method and asks that one the provider does not
 * switch on be answered as such: the three it serves are three routes on this one path, so the router
 * answers the 405 of §2.3 for a fourth and nothing here is written for it. The provider serves all three,
 * so it never owes that answer of itself, and it allows every client that holds its own token, so it never
 * owes the 403 of §2.1 either: what a client may do to its own registration is not a permission this
 * provider hands out separately.
 */
#[AsController]
final readonly class ClientConfigurationReadController
{
    public const string ROUTE = 'beffroi_protocol_client_configuration_read';

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
