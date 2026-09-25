<?php

declare(strict_types=1);

namespace Heidi\Bundle\Load;

use Heidi\Bundle\Http\InteractionPages;
use Heidi\Bundle\Http\ProtocolAnswer;
use Heidi\Bundle\Plane\Plane;
use Heidi\Oidc\Domain\Token\TokenErrorResponse;
use Heidi\Oidc\Domain\Token\TokenResponse;
use Symfony\Component\HttpFoundation\Response;

/**
 * What a request refused for load is answered (decision 0014), written once so that a refusal has one
 * form wherever it happens: `429` (RFC 6585 §4) with the `Retry-After` that code provides for
 * (RFC 9110 §10.2.3 for the syntax) and `Cache-Control: no-store`, the shape RFC 9126 §2.3 names for
 * the pushed authorization request endpoint, in the media type of the plane the route belongs to.
 *
 * The body of the protocol plane carries no `error` member. The values of that member are registered
 * (RFC 6749 §11.4), none of them says a budget is spent, and an invented one is read by a client as a
 * protocol error to act on when the only thing to do is wait out the header; `slow_down` is not that
 * value either, RFC 8628 §3.5 giving it the meaning of a request still pending. What is left is the
 * explanation RFC 6585 §4 asks for, under the name the specification gives a human-readable
 * explanation, for the developer who reads the response and not for the client that parses it.
 */
final readonly class LoadRefusal
{
    public const int STATUS = Response::HTTP_TOO_MANY_REQUESTS;

    /**
     * The code the error page of the interaction plane carries, as the code page names
     * `too_many_attempts`: a fact of the request and not of the account, and saying it teaches an
     * attacker nothing.
     */
    public const string PAGE_ERROR = 'too_many_requests';

    public const string DESCRIPTION = 'Too many requests were sent to this provider; this one was not served. Try again after the delay the Retry-After header gives.';

    public function __construct(
        private InteractionPages $pages,
    ) {
    }

    /**
     * @param Plane|null $plane the plane of the route the request was matched to
     * @param int $retryAfter seconds before the window has room again
     */
    public function response(?Plane $plane, int $retryAfter): Response
    {
        // the interaction plane answers a browser, everything else answers a machine
        return (
            $plane === Plane::Interaction
                ? $this->pages->error(self::STATUS, self::PAGE_ERROR, headers: self::retryAfter($retryAfter))
                : ProtocolAnswer::json(
                    ['error_description' => self::DESCRIPTION],
                    self::STATUS,
                    TokenErrorResponse::CONTENT_TYPE,
                    self::retryAfter($retryAfter) + TokenResponse::HEADERS,
                )
        );
    }

    /**
     * @return array<string, string>
     */
    private static function retryAfter(int $retryAfter): array
    {
        return [
            'Retry-After' => (string) $retryAfter,
        ];
    }
}
