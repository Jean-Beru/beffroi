<?php

declare(strict_types=1);

namespace Heidi\Bundle\Http;

use Heidi\Bundle\Controller\LoginController;
use function is_array;
use function is_string;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

/**
 * The page of this provider that asked for a login and where the browser goes once it has one
 * (architecture §5.2, §5.4). Most pages that need a signed-in user are the pages of an authorization
 * request and are named by their interaction; the page where a user approves what an appliance asked
 * (RFC 8628 §3.3) is not, and it is the login of the same firewall that it needs.
 *
 * What is remembered is a route of this provider and the parameters our own code wrote, in the HTTP
 * session and never in the request: the login page reads no target path from a body, a query or a referer,
 * so a browser is never sent anywhere by whoever filled the form.
 *
 * It is forgotten by the page that was waiting for it, and not by the login that answered: a password
 * verified for a user who holds a second factor is not a login yet (SecondFactorGate), and a page that let
 * go of what it was waiting for at the first step would have nowhere to send the browser after the second.
 */
final readonly class LoginTarget
{
    public const string SESSION_KEY = '_heidi_login_target';

    public function __construct(
        private InteractionPages $pages,
    ) {
    }

    /**
     * Remembers the page and sends the browser to the login of the firewall, which is the login every other
     * page of the provider uses.
     *
     * @param string $route a route of this provider
     * @param array<string, string> $parameters what our own code writes into it, never what a request carried
     */
    public function sendToLogin(SessionInterface $httpSession, string $route, array $parameters = []): RedirectResponse
    {
        $httpSession->set(self::SESSION_KEY, [
            'route' => $route,
            'parameters' => $parameters,
        ]);

        return $this->pages->redirectToRoute(LoginController::ROUTE);
    }

    /**
     * Whether a page of this provider is waiting for a login, which is what makes the login page worth
     * showing to a browser that named no interaction.
     */
    public function isPending(SessionInterface $httpSession): bool
    {
        return self::remembered($httpSession) !== null;
    }

    public function forget(SessionInterface $httpSession): void
    {
        $httpSession->remove(self::SESSION_KEY);
    }

    /**
     * The redirection to the page that asked, or null when none asked.
     */
    public function resume(SessionInterface $httpSession): ?RedirectResponse
    {
        $remembered = self::remembered($httpSession);

        return $remembered === null ? null : $this->pages->redirectToRoute($remembered['route'], $remembered['parameters']);
    }

    /**
     * @return array{route: string, parameters: array<string, string>}|null
     */
    private static function remembered(SessionInterface $httpSession): ?array
    {
        $remembered = $httpSession->get(self::SESSION_KEY);
        if (! is_array($remembered)) {
            return null;
        }
        $route = $remembered['route'] ?? null;
        $parameters = $remembered['parameters'] ?? null;
        if (! is_string($route) || $route === '' || ! is_array($parameters)) {
            return null;
        }
        $written = [];
        foreach ($parameters as $name => $value) {
            if (is_string($name) && is_string($value)) {
                $written[$name] = $value;
            }
        }

        return [
            'route' => $route,
            'parameters' => $written,
        ];
    }
}
