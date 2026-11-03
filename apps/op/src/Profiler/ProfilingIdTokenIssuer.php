<?php

declare(strict_types=1);

namespace App\Profiler;

use DateTimeImmutable;
use Beffroi\Oidc\Domain\Token\AddressedIdToken;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Token\AccessToken;
use Beffroi\Oidc\Domain\Token\UserAuthorizationInterface;
use Beffroi\Oidc\Exception\InvalidJwtException;
use Beffroi\Oidc\Port\CompactJwtReaderInterface;
use Beffroi\Oidc\Port\IdTokenIssuerInterface;
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
        private CompactJwtReaderInterface $jwts,
        private PanelValues $values,
    ) {
    }

    public function address(Client $client): AddressedIdToken
    {
        return $this->issuer->address($client);
    }

    public function issue(UserAuthorizationInterface $authorization, AccessToken $accessToken, AddressedIdToken $addressed, DateTimeImmutable $now): string
    {
        $idToken = $this->issuer->issue($authorization, $accessToken, $addressed, $now);
        $requested = $authorization->claimsRequest->idToken ?? [];
        $this->profile->record(new Observation('Tokens', 'ID token', [
            'aud' => $authorization->client->registration->clientId,
            'shape' => RegisteredShape::of($authorization->client->registration->idToken),
            'nonce' => $authorization->nonce === null ? 'none' : 'carried back',
            'acr' => $authorization->authentication->contextClass,
            'amr' => implode(' ', $authorization->authentication->methods),
            'auth_time' => $authorization->authentication->authenticatedAt->format(DATE_ATOM),
            'claims the client asked for by name' => $requested === [] ? 'none' : implode(', ', array_keys($requested)),
            'claims it carries' => $this->claimsOf($idToken),
        ]));

        return $idToken;
    }

    /**
     * What the document the client will read says of itself. A token encrypted to the client is one
     * string here and stays one: what hides it is what the client registered, and the panel does not
     * undo it to look inside.
     */
    private function claimsOf(string $idToken): string
    {
        try {
            return $this->values->all($this->jwts->read($idToken)->claims);
        } catch (InvalidJwtException) {
            return 'encrypted for the client, and not opened here';
        }
    }
}
