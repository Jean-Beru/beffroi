<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\ProtocolAnswer;
use Heidi\Oidc\Application\Client\Registration\ClientRegistrationHandler;
use Heidi\Oidc\Domain\Client\Registration\ClientRegistrationResponse;
use Heidi\Oidc\Domain\Client\Registration\RegistrationErrorResponse;
use Heidi\Oidc\Domain\Client\Registration\RegistrationRequest;
use Heidi\Oidc\Exception\ClientRegistrationNotOfferedException;
use Heidi\Oidc\Exception\InvalidClientMetadataException;
use Heidi\Oidc\Exception\UnauthorizedRegistrationException;
use Heidi\Oidc\Exception\UnreadableClientMetadataException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Attribute\Route;
use Throwable;

/**
 * The client registration endpoint (RFC 7591 §3.1), POST only: a JSON object in, a 201 carrying what was
 * registered out (§3.2.1), and the refusals of §3.2.2 as JSON.
 *
 * A tenant that registers nobody has no endpoint here rather than one that refuses what it read
 * (decision 0009), which is a 404 and the same thing the absence of "registration_endpoint" says in the
 * discovery document of that tenant. A request that presents nothing authorising a registration is a 401
 * carrying the challenge an endpoint that reads a bearer credential owes (RFC 6750 §3).
 */
#[AsController]
final readonly class ClientRegistrationController
{
    public const string ROUTE = 'heidi_protocol_client_registration';

    public function __construct(
        private TenantProvider $tenants,
        private ClientRegistrationHandler $handler,
    ) {
    }

    #[Route('/register', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        try {
            $response = $this->handler->handle(
                $this->tenants->provide(),
                new RegistrationRequest(self::members($request), $request->headers->get('Authorization')),
            );
        } catch (ClientRegistrationNotOfferedException $exception) {
            throw new NotFoundHttpException($exception->getMessage(), $exception);
        } catch (UnauthorizedRegistrationException $exception) {
            return ProtocolAnswer::error($exception, [
                'WWW-Authenticate' => $exception->challenge(),
            ] + ClientRegistrationResponse::HEADERS);
        } catch (UnreadableClientMetadataException $exception) {
            return ProtocolAnswer::json(
                RegistrationErrorResponse::fromException($exception)->parameters(),
                RegistrationErrorResponse::STATUS_CODE,
                RegistrationErrorResponse::CONTENT_TYPE,
                ClientRegistrationResponse::HEADERS,
            );
        }

        return ProtocolAnswer::json(
            $response->parameters(),
            ClientRegistrationResponse::STATUS_CODE,
            ClientRegistrationResponse::CONTENT_TYPE,
            ClientRegistrationResponse::HEADERS,
        );
    }

    /**
     * RFC 7591 §3.1: the body is a JSON object whose members are the metadata. A body that is not one
     * carries no metadata at all, which is what "invalid_client_metadata" says of it; a member whose
     * name is a number is a member nobody reads, and is refused where every unknown member is.
     *
     * @throws InvalidClientMetadataException
     *
     * @return array<string, mixed>
     */
    private static function members(Request $request): array
    {
        try {
            $members = $request->toArray();
        } catch (Throwable $exception) {
            throw new InvalidClientMetadataException(
                null,
                null,
                'The body of a registration request is a JSON object (RFC 7591 section 3.1).',
                $exception,
            );
        }
        $named = [];
        foreach ($members as $member => $value) {
            $named[(string) $member] = $value;
        }

        return $named;
    }
}
