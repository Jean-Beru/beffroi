<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use Beffroi\Oidc\Domain\Client\Registration\ClientInformationResponse;
use Beffroi\Oidc\Domain\Client\Registration\RegistrationErrorResponse;
use Beffroi\Oidc\Exception\UnauthorizedBearerRequestException;
use Beffroi\Oidc\Exception\UnreadableClientMetadataException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * How the four endpoints where a client is registered, read, replaced and deleted put their answers on the
 * wire (RFC 7591 §3.2, RFC 7592 §2, §3). Four endpoints answering the same three things is one place here
 * and not four: what the provider says of a client, the refusal of a registration that does not hold, and
 * the challenge an endpoint that reads a bearer credential owes on a 401 (RFC 6750 §3).
 *
 * Reading the body is here for the same reason: a registration and a replacement are the same JSON object
 * of RFC 7591 §3.1 read the same way, and a body that is not one carries no metadata at all.
 */
final readonly class ClientRegistrationAnswer
{
    public static function information(ClientInformationResponse $response): Response
    {
        return ProtocolAnswer::json(
            $response->parameters(),
            $response->statusCode,
            ClientInformationResponse::CONTENT_TYPE,
            ClientInformationResponse::HEADERS,
        );
    }

    /**
     * RFC 7592 §2.3: a client that deleted itself is answered nothing, because there is nothing left to
     * answer about it.
     */
    public static function gone(): Response
    {
        return new Response(null, Response::HTTP_NO_CONTENT, ClientInformationResponse::HEADERS);
    }

    public static function refusal(UnreadableClientMetadataException $exception): Response
    {
        return ProtocolAnswer::json(
            RegistrationErrorResponse::fromException($exception)->parameters(),
            RegistrationErrorResponse::STATUS_CODE,
            RegistrationErrorResponse::CONTENT_TYPE,
            ClientInformationResponse::HEADERS,
        );
    }

    public static function challenge(UnauthorizedBearerRequestException $exception): Response
    {
        return ProtocolAnswer::error($exception, [
            'WWW-Authenticate' => $exception->challenge(),
        ] + ClientInformationResponse::HEADERS);
    }

    /**
     * RFC 7591 §3.1: the body is a JSON object whose members are the metadata. A body that is not one
     * carries no metadata at all, and what that is worth is the module's to decide, in the order it
     * refuses things; a member whose name is a number is a member nobody reads, and is refused where every
     * unknown member is.
     *
     * @return array<string, mixed>|null null when the body is no JSON object
     */
    public static function members(Request $request): ?array
    {
        try {
            $members = $request->toArray();
        } catch (Throwable) {
            return null;
        }
        $named = [];
        foreach ($members as $member => $value) {
            $named[(string) $member] = $value;
        }

        return $named;
    }
}
