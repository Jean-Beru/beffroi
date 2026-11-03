<?php

declare(strict_types=1);

namespace App\Http;

use Beffroi\Oidc\Domain\Token\JwtPayload;
use Beffroi\Oidc\Domain\Token\TokenErrorResponse;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Symfony\Component\HttpFoundation\Response;

/**
 * How an endpoint of the protocol plane puts an answer of the module on the wire: the content type the
 * answer names, the headers it carries, and the body it is. The module decides what is said and with
 * which status; this only writes it down.
 *
 * The refusal is the same at every endpoint that answers in JSON (RFC 6749 §5.2), so it is written here
 * once rather than at each of them.
 */
final readonly class ProtocolAnswer
{
    /**
     * @param array<string, string> $headers what the answer carries beside its content type
     */
    public static function document(string $body, int $statusCode, string $contentType, array $headers = []): Response
    {
        return new Response($body, $statusCode, [
            'Content-Type' => $contentType,
        ] + $headers);
    }

    /**
     * @param array<string, mixed> $parameters
     * @param array<string, string> $headers
     */
    public static function json(array $parameters, int $statusCode, string $contentType, array $headers = []): Response
    {
        return self::document(JwtPayload::encode($parameters), $statusCode, $contentType, $headers);
    }

    /**
     * @param array<string, string> $headers what the endpoint carries on every answer, the refusals included
     */
    public static function error(OAuth2Exception $exception, array $headers = []): Response
    {
        $error = TokenErrorResponse::fromException($exception);

        return self::json($error->parameters(), $error->statusCode, TokenErrorResponse::CONTENT_TYPE, $headers + $error->headers());
    }
}
