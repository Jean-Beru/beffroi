<?php

declare(strict_types=1);

namespace Heidi\Bundle\Profiler;

use DateTimeImmutable;
use Heidi\Oidc\Domain\Token\AccessToken;
use Heidi\Oidc\Domain\Token\AuthorizationInterface;
use Heidi\Oidc\Domain\Token\UserAuthorizationInterface;
use Heidi\Oidc\Exception\InvalidJwtException;
use Heidi\Oidc\Port\AccessTokenIssuerInterface;
use Heidi\Oidc\Port\CompactJwtReaderInterface;
use function implode;
use function sprintf;
use const DATE_ATOM;

/**
 * The access token the token endpoint just handed out, said without its value: the grant it answers, the
 * shape the client is registered for, what it is good for and what it is bound to (RFC 8705 §3.1,
 * RFC 9449 §6.1). A thumbprint is what a resource server is meant to compare and is not a secret; the
 * token itself never reaches the panel.
 *
 * The "jti" is the one thing about a token that only the token says, so it is read back from it, the one
 * claim of it that is kept. A token that is not a JWT carries no claim at all, which is what its shape
 * being opaque means, and the panel says so rather than guessing.
 *
 * What the session had proven is said of a token somebody signed in for, and of a token a client holds for
 * itself the panel says that nobody did (RFC 6749 §4.4) rather than showing three empty rows.
 */
final readonly class ProfilingAccessTokenIssuer implements AccessTokenIssuerInterface
{
    public function __construct(
        private AccessTokenIssuerInterface $issuer,
        private OpProfile $profile,
        private CompactJwtReaderInterface $jwts,
    ) {
    }

    public function issue(AuthorizationInterface $authorization, DateTimeImmutable $now): AccessToken
    {
        $token = $this->issuer->issue($authorization, $now);
        $confirmation = $authorization->confirmation;
        $this->profile->record(new Observation('Tokens', 'Access token', [
            'grant' => $authorization->grantType->value,
            'shape' => $authorization->client->registration->accessTokenShape->name(),
            'jti' => $this->jtiOf($token),
            'aud' => implode(' ', $authorization->audience()->values),
            'exp' => $token->expiresAt->format(DATE_ATOM),
            'scopes of this response' => (string) $authorization->scopes,
            'scopes granted' => (string) $authorization->grantedScopes,
            'binding' => $confirmation === null ? 'bearer' : sprintf('cnf.%s %s', $confirmation->member(), $confirmation->value()),
            ...self::whoSignedIn($authorization),
        ]));

        return $token;
    }

    /**
     * @return array<string, string>
     */
    private static function whoSignedIn(AuthorizationInterface $authorization): array
    {
        if (! $authorization instanceof UserAuthorizationInterface) {
            return [
                'signed in' => 'nobody: the client asked for itself',
            ];
        }

        return [
            'acr' => $authorization->authentication->contextClass,
            'amr' => implode(' ', $authorization->authentication->methods),
            'auth_time' => $authorization->authentication->authenticatedAt->format(DATE_ATOM),
        ];
    }

    private function jtiOf(AccessToken $token): string
    {
        try {
            return $this->jwts->read($token->value)->claim('jti') ?? 'none';
        } catch (InvalidJwtException) {
            return 'none: the token carries no claims';
        }
    }
}
