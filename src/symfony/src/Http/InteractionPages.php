<?php

declare(strict_types=1);

namespace Heidi\Bundle\Http;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;
use Twig\Environment;

/**
 * The responses of the interaction plane (architecture §5.2): pages rendered from the templates of the
 * bundle, which an application overrides under "templates/bundles/HeidiBundle/", and redirections. Every
 * one of them carries the headers the pages of a provider need: no framing (RFC 9700 §4.15, both the
 * header browsers have honoured for years and the directive that replaces it), no referrer, because the
 * URLs of these pages carry an interaction identifier and the redirections carry a code or a state
 * (a Referrer-Policy on a redirection applies to the redirected request), and no caching, because every
 * page holds a form token or a state of the flow. The pages extend the layout of the bundle, which an
 * application overrides first to give them its look; their words are in the "heidi" translation domain,
 * in the locale InteractionLocale chose (architecture §5.7).
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
     * The page shown when a request cannot go on and nothing may be sent back to a client: an error the
     * authorization endpoint found before validating the redirect URI (RFC 9700 §4.1), an error of a
     * logout request (RP-Initiated Logout §4), an interaction that expired or was already completed. What
     * the user reads is the sentence the template has for the code, in the locale of the request
     * (architecture §5.7); the description, when there is one, is shown to them as the detail the
     * developer of the application needs.
     *
     * @param string $error a code the template translates: "invalid_request", or one of the constants of AuthorizationResponder and of the controllers
     * @param string|null $description the error_description of the protocol (RFC 6749 §4.1.2.1), in the language of the specification; never an internal message
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
