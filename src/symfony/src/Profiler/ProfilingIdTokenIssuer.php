<?php

declare(strict_types=1);

namespace Heidi\Bundle\Profiler;

use DateTimeImmutable;
use Heidi\Oidc\Domain\Token\AccessToken;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Port\IdTokenIssuerInterface;
use function array_keys;
use function implode;
use const DATE_ATOM;

/**
 * The ID token the token endpoint just handed out (OIDC Core §2), said without its value: whom it names
 * itself to, what the session had proven when the authorization was granted, and the shape the client
 * registered for it. Which key signed it is the key observer's to say.
 *
 * The claims of an ID token are the user, which decision 0011 keeps out of anything written down; the
 * names of the ones the client asked for are what the panel shows of them.
 */
final readonly class ProfilingIdTokenIssuer implements IdTokenIssuerInterface
{
    public function __construct(
        private IdTokenIssuerInterface $issuer,
        private OpProfile $profile,
    ) {
    }

    public function issue(GrantedAuthorization $authorization, AccessToken $accessToken, DateTimeImmutable $now): string
    {
        $idToken = $this->issuer->issue($authorization, $accessToken, $now);
        $requested = $authorization->claimsRequest->idToken ?? [];
        $this->profile->record(new Observation('ID token', [
            'aud' => $authorization->client->clientId,
            'shape' => RegisteredShape::of($authorization->client->idToken),
            'nonce' => $authorization->nonce === null ? 'none' : 'carried back',
            'acr' => $authorization->authentication->contextClass,
            'amr' => implode(' ', $authorization->authentication->methods),
            'auth_time' => $authorization->authentication->authenticatedAt->format(DATE_ATOM),
            'claims the client asked for by name' => $requested === [] ? 'none' : implode(', ', array_keys($requested)),
        ]));

        return $idToken;
    }
}
