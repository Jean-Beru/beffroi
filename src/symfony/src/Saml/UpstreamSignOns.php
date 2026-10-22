<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use function array_key_exists;
use function array_slice;
use Beffroi\Bundle\Http\WaitingPage;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Saml\Domain\Upstream\SentAuthnRequest;
use function is_array;
use function is_string;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

/**
 * The requests the service provider of a tenant sent upstream identity providers for the logins of a browser
 * (beffroi/saml, spec/saml.md S-50): kept in the HTTP session of that browser and never in a URL, each under the
 * reference its RelayState carries, 32 bytes of random_bytes() and nothing else, with the ID of the request, the entity
 * ID of the provider it was sent to, the tenant, and the interaction it serves or, for the login a page of the provider
 * waits for (S-51), that page as LoginTarget remembered it when the request was sent; at most eight, the oldest
 * forgotten first, as the requests that wait for a login are kept (WaitingSignOns). The assertion consumer service reads
 * there what a response answers and which interaction or page it resumes (issue #784); another browser holds none of
 * them.
 *
 * @phpstan-type Kept array{tenant: string, interaction: string, request: string, identity_provider: string}|array{tenant: string, page: array{route: string, parameters: array<string, string>}, request: string, identity_provider: string}
 */
final readonly class UpstreamSignOns
{
    public const string SESSION_KEY = '_beffroi_saml_upstream_sign_ons';

    public const int MAX_KEPT = 8;

    public function keep(SessionInterface $httpSession, Tenant $tenant, Interaction|WaitingPage $for, SentAuthnRequest $sent): void
    {
        $kept = self::kept($httpSession);
        $kept[$sent->request->relayState] = $for instanceof Interaction
            ? [
                'tenant' => $tenant->id->toRfc4122(),
                'interaction' => $for->id,
                'request' => $sent->id,
                'identity_provider' => $sent->request->identityProvider,
            ]
            : [
                'tenant' => $tenant->id->toRfc4122(),
                'page' => [
                    'route' => $for->route,
                    'parameters' => $for->parameters,
                ],
                'request' => $sent->id,
                'identity_provider' => $sent->request->identityProvider,
            ];
        $httpSession->set(self::SESSION_KEY, array_slice($kept, -self::MAX_KEPT, preserve_keys: true));
    }

    /**
     * What the session holds, an entry that is not one left out.
     *
     * @return array<string, Kept>
     */
    private static function kept(SessionInterface $httpSession): array
    {
        $stored = $httpSession->get(self::SESSION_KEY);
        if (! is_array($stored)) {
            return [];
        }
        $kept = [];
        foreach ($stored as $reference => $entry) {
            if (
                ! is_string($reference)
                || ! is_array($entry)
                || ! is_string($entry['tenant'] ?? null)
                || ! is_string($entry['request'] ?? null)
                || ! is_string($entry['identity_provider'] ?? null)
            ) {
                continue;
            }
            $interaction = $entry['interaction'] ?? null;
            $page = self::page($entry['page'] ?? null);
            if (is_string($interaction) && ! array_key_exists('page', $entry)) {
                $kept[$reference] = [
                    'tenant' => $entry['tenant'],
                    'interaction' => $interaction,
                    'request' => $entry['request'],
                    'identity_provider' => $entry['identity_provider'],
                ];
            } elseif ($page !== null && ! array_key_exists('interaction', $entry)) {
                $kept[$reference] = [
                    'tenant' => $entry['tenant'],
                    'page' => $page,
                    'request' => $entry['request'],
                    'identity_provider' => $entry['identity_provider'],
                ];
            }
        }

        return $kept;
    }

    /**
     * The page an entry serves, as keep() wrote it; null when it is not one.
     *
     * @return array{route: string, parameters: array<string, string>}|null
     */
    private static function page(mixed $page): ?array
    {
        if (! is_array($page) || ! is_string($page['route'] ?? null) || ! is_array($page['parameters'] ?? null)) {
            return null;
        }
        $parameters = [];
        foreach ($page['parameters'] as $name => $value) {
            if (! is_string($name) || ! is_string($value)) {
                return null;
            }
            $parameters[$name] = $value;
        }

        return [
            'route' => $page['route'],
            'parameters' => $parameters,
        ];
    }
}
