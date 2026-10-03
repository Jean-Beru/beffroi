<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use Symfony\Component\HttpFoundation\HeaderUtils;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Twig\Environment;

/**
 * The responses of the interaction plane (architecture §5.2): pages from the templates of the bundle,
 * which an application overrides, and redirections, every one with the headers a provider needs: no
 * framing (RFC 9700 §4.15), no referrer, no caching.
 */
final readonly class InteractionPages
{
    /**
     * The browser holds no session of the core and the page needs one; nothing is sent back to a client,
     * a page of the account belongs to none.
     */
    public const string LOGIN_REQUIRED = 'login_required';

    /**
     * A form of an interaction or of the account came back without the token it was rendered with.
     */
    public const string INVALID_CSRF_TOKEN = 'invalid_csrf_token';

    public const array HEADERS = [
        'X-Frame-Options' => 'DENY',
        'Content-Security-Policy' => "frame-ancestors 'none'",
        'Referrer-Policy' => 'no-referrer',
        'Cache-Control' => 'no-store',
    ];

    public function __construct(
        private Environment $twig,
        private UrlGeneratorInterface $router,
    ) {
    }

    /**
     * What the pages show of their tenant is not in this context (issue #449): the layout, and the two
     * pages that name the provider in a sentence, read "beffroi_tenant()", so a page passes nothing that
     * the layout shows and a page that asks for nothing costs nothing (Twig\TenantExtension).
     *
     * @param array<string, mixed> $context
     * @param array<string, string> $headers what this page carries over the headers of the plane, a
     *                                       stricter Content-Security-Policy for one
     */
    public function render(string $template, array $context = [], int $status = Response::HTTP_OK, array $headers = []): Response
    {
        return new Response($this->twig->render('@Beffroi/' . $template, $context), $status, $headers + self::HEADERS);
    }

    /**
     * The page shown when nothing may be sent back to a client (RFC 9700 §4.1, RP-Initiated Logout §4).
     *
     * @param string $error a code the template translates
     * @param string|null $description the error_description of the protocol, never an internal message
     * @param array<string, string> $headers what this refusal carries over the headers of the plane, the
     *                                       Retry-After of a budget that is spent for one
     */
    public function error(int $status, string $error, ?string $description = null, array $headers = []): Response
    {
        return $this->render(
            'error.html.twig',
            [
                'status' => $status,
                'error' => $error,
                'description' => $description,
            ],
            $status,
            $headers,
        );
    }

    /**
     * A file this provider hands a person, with the headers of the plane and the two of a download: the
     * archive of everything held about them (issue #453) is the one there is, and it is not cached, not
     * framed and not referred, as every answer of this plane is.
     *
     * The file name is the caller's, and it names the thing and never the person: it travels in a header
     * that proxies and browsers write down.
     */
    public function download(string $content, string $mediaType, string $fileName): Response
    {
        return new Response($content, Response::HTTP_OK, [
            'Content-Type' => $mediaType,
            'Content-Disposition' => HeaderUtils::makeDisposition(HeaderUtils::DISPOSITION_ATTACHMENT, $fileName),
        ] + self::HEADERS);
    }

    /**
     * Where a form of these pages comes back to (issue #481): the page it was sent from, by a redirection
     * a browser re-issues as a GET, so that reloading that page does not post the form again.
     *
     * 303 and not 302, which is what RFC 9110 §15.4.4 says of an answer to a POST that is not itself the
     * result of it: a browser is told to go and read the page, not to repeat what it sent. What was refused
     * crosses it in the session (WhatWasRefused), and the page that answers does so with 200: a page being
     * read is not an unprocessable entity, whatever was refused a moment ago.
     *
     * @param array<string, string> $parameters
     */
    public function afterTheForm(string $route, array $parameters = []): RedirectResponse
    {
        return new RedirectResponse($this->router->generate($route, $parameters), Response::HTTP_SEE_OTHER, self::HEADERS);
    }

    public function redirect(string $uri): RedirectResponse
    {
        return new RedirectResponse($uri, Response::HTTP_FOUND, self::HEADERS);
    }

    /**
     * A redirection to a page of the interaction the query of the request names (?interaction=), the
     * way the login page and what posts to it carry it (§4.3), or to the page alone when it names none;
     * the identifier is never read from the body nor from a referer.
     */
    public function redirectToPage(string $route, Request $request): RedirectResponse
    {
        $interaction = $request->query->getString(AuthorizationResponder::INTERACTION_PARAMETER);

        return $this->redirectToRoute(
            $route,
            $interaction === ''
                ? []
                : [
                    AuthorizationResponder::INTERACTION_PARAMETER => $interaction,
                ],
        );
    }

    /**
     * A redirection to a page of this provider with the parameters our own code wrote: what a page waiting
     * for a login is resumed by (LoginTarget), and what the redirection above is made of.
     *
     * @param array<string, string> $parameters
     */
    public function redirectToRoute(string $route, array $parameters = []): RedirectResponse
    {
        return $this->redirect($this->router->generate($route, $parameters));
    }
}
