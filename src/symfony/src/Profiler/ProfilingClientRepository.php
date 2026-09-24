<?php

declare(strict_types=1);

namespace Heidi\Bundle\Profiler;

use function array_map;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Port\ClientRepositoryInterface;
use function implode;

/**
 * The client the request named, as the provider resolved it: who it is, what it registered and what the
 * endpoints therefore hold it to. The authentication method is the one the client registered, which is
 * also the one the authenticator accepted, a request presenting any other being refused before it
 * reaches anything (RFC 6749 §2.3); it is read off the client and never off a list kept beside it.
 *
 * The secret of a client never leaves the client, and nothing of it is read here.
 */
final readonly class ProfilingClientRepository implements ClientRepositoryInterface
{
    public function __construct(
        private ClientRepositoryInterface $clients,
        private OpProfile $profile,
    ) {
    }

    public function findByClientId(Tenant $tenant, string $clientId): ?Client
    {
        $client = $this->clients->findByClientId($tenant, $clientId);
        if ($client !== null) {
            $this->profile->record(self::observe($client));
        }

        return $client;
    }

    private static function observe(Client $client): Observation
    {
        return new Observation('Client', 'Client', [
            'client_id' => $client->registration->clientId,
            'name' => $client->registration->name,
            'authentication method' => $client->registration->authenticationMethod->name(),
            'pushed authorization request' => $client->registration->requiresPushedAuthorizationRequests ? 'required' : 'not required',
            'PKCE' => $client->registration->requiresPkce ? 'required' : 'not required',
            'consent' => $client->registration->requiresConsent ? 'asked' : 'not asked',
            'grant types' => implode(', ', array_map(static fn (GrantType $grant): string => $grant->value, $client->registration->grantTypes)),
            'allowed scopes' => (string) $client->registration->allowedScopes,
            'access token' => $client->registration->accessTokenFormat->value,
            'ID token' => RegisteredShape::of($client->registration->idToken),
            'UserInfo' => RegisteredShape::of($client->registration->userInfo),
            'authorization response' => RegisteredShape::of($client->registration->authorizationResponse),
        ]);
    }
}
