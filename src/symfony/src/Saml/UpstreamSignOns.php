<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use function array_slice;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Saml\Domain\Upstream\SentAuthnRequest;
use function is_array;
use function is_string;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

/**
 * The requests the service provider of a tenant sent upstream identity providers for the interactions of a browser
 * (beffroi/saml, spec/saml.md S-50): kept in the HTTP session of that browser and never in a URL, each under the
 * reference its RelayState carries, 32 bytes of random_bytes() and nothing else, with the ID of the request, the entity
 * ID of the provider it was sent to, the interaction it serves and the tenant; at most eight, the oldest forgotten
 * first, as the requests that wait for a login are kept (WaitingSignOns). The assertion consumer service reads there
 * what a response answers (issue #784); another browser holds none of them.
 */
final readonly class UpstreamSignOns
{
    public const string SESSION_KEY = '_beffroi_saml_upstream_sign_ons';

    public const int MAX_KEPT = 8;

    public function keep(SessionInterface $httpSession, Tenant $tenant, Interaction $interaction, SentAuthnRequest $sent): void
    {
        $kept = self::kept($httpSession);
        $kept[$sent->request->relayState] = [
            'tenant' => $tenant->id->toRfc4122(),
            'interaction' => $interaction->id,
            'request' => $sent->id,
            'identity_provider' => $sent->request->identityProvider,
        ];
        $httpSession->set(self::SESSION_KEY, array_slice($kept, -self::MAX_KEPT, preserve_keys: true));
    }

    /**
     * What the session holds, an entry that is not one left out.
     *
     * @return array<string, array{tenant: string, interaction: string, request: string, identity_provider: string}>
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
                is_string($reference)
                && is_array($entry)
                && is_string($entry['tenant'] ?? null)
                && is_string($entry['interaction'] ?? null)
                && is_string($entry['request'] ?? null)
                && is_string($entry['identity_provider'] ?? null)
            ) {
                $kept[$reference] = [
                    'tenant' => $entry['tenant'],
                    'interaction' => $entry['interaction'],
                    'request' => $entry['request'],
                    'identity_provider' => $entry['identity_provider'],
                ];
            }
        }

        return $kept;
    }
}
