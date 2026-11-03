<?php

declare(strict_types=1);

namespace App\Http;

use function is_string;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

/**
 * The token a page of the provider posts back with its form, and the one refusal a page that does not
 * carry it gets. Every page that posts asks here: the pages of an interaction, which read their
 * parameters with the rules of RFC 6749 §3.1, and the pages of the account, which read the body of the
 * request; what differs is where the value is read, never what makes it hold nor what is answered.
 */
final readonly class FormToken
{
    /**
     * The name of the field the templates render.
     */
    public const string PARAMETER = '_token';

    public function __construct(
        private CsrfTokenManagerInterface $csrf,
        private InteractionPages $pages,
    ) {
    }

    /**
     * @param mixed $token the value as the caller read it, whatever it turned out to be
     */
    public function holds(mixed $token, string $csrfTokenId): bool
    {
        return is_string($token) && $token !== '' && $this->csrf->isTokenValid(new CsrfToken($csrfTokenId, $token));
    }

    /**
     * The page a request without the token gets, null when it carries it.
     */
    public function refusal(mixed $token, string $csrfTokenId): ?Response
    {
        return $this->holds($token, $csrfTokenId)
            ? null
            : $this->pages->error(Response::HTTP_FORBIDDEN, InteractionPages::INVALID_CSRF_TOKEN);
    }
}
