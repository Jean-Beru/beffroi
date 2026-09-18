<?php

declare(strict_types=1);

namespace Heidi\Bundle\Http;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;
use Twig\Environment;

/**
 * The responses of the interaction plane (architecture §5.2): pages from the templates of the bundle,
 * which an application overrides, and redirections, every one with the headers a provider needs: no
 * framing (RFC 9700 §4.15), no referrer, no caching.
 */
final readonly class InteractionPages
{
    public const array HEADERS = [
        'X-Frame-Options' => 'DENY',
        'Content-Security-Policy' => "frame-ancestors 'none'",
        'Referrer-Policy' => 'no-referrer',
        'Cache-Control' => 'no-store',
    ];

    public function __construct(
        private Environment $twig,
    ) {
    }

    /**
     * @param array<string, mixed> $context
     */
    public function render(string $template, array $context = [], int $status = Response::HTTP_OK): Response
    {
        return new Response($this->twig->render('@Heidi/' . $template, $context), $status, self::HEADERS);
    }

    /**
     * The page shown when nothing may be sent back to a client (RFC 9700 §4.1, RP-Initiated Logout §4).
     *
     * @param string $error a code the template translates
     * @param string|null $description the error_description of the protocol, never an internal message
     */
    public function error(int $status, string $error, ?string $description = null): Response
    {
        return $this->render('error.html.twig', [
            'status' => $status,
            'error' => $error,
            'description' => $description,
        ], $status);
    }

    public function redirect(string $uri): RedirectResponse
    {
        return new RedirectResponse($uri, Response::HTTP_FOUND, self::HEADERS);
    }
}
