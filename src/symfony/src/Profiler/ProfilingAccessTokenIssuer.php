<?php

declare(strict_types=1);

namespace Heidi\Bundle\Profiler;

use function array_map;
use DateTimeImmutable;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\AccessToken;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
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
 */
final readonly class ProfilingAccessTokenIssuer implements AccessTokenIssuerInterface
{
    public function __construct(
        private AccessTokenIssuerInterface $issuer,
        private OpProfile $profile,
        private CompactJwtReaderInterface $jwts,
    ) {
    }

    public function issue(GrantedAuthorization $authorization, DateTimeImmutable $now): AccessToken
    {
        $token = $this->issuer->issue($authorization, $now);
        $confirmation = $authorization->confirmation;
        $this->profile->record(new Observation('Access token', [
            'grant' => $authorization->grantType->value,
            'form' => $authorization->client->accessTokenFormat->value,
            'jti' => $this->jtiOf($token),
            'aud' => $authorization->client->clientId,
            'exp' => $token->expiresAt->format(DATE_ATOM),
            'scopes of this response' => self::list($authorization->scopes),
            'scopes granted' => self::list($authorization->grantedScopes),
            'binding' => $confirmation === null ? 'bearer' : sprintf('cnf.%s %s', $confirmation->member(), $confirmation->value()),
            'acr' => $authorization->authentication->contextClass,
            'amr' => implode(' ', $authorization->authentication->methods),
            'auth_time' => $authorization->authentication->authenticatedAt->format(DATE_ATOM),
        ]));

        return $token;
    }

    private function jtiOf(AccessToken $token): string
    {
        try {
            return $this->jwts->read($token->value)->claim('jti') ?? 'none';
        } catch (InvalidJwtException) {
            return 'none: the token carries no claims';
        }
    }

    /**
     * @param list<Scope> $scopes
     */
    private static function list(array $scopes): string
    {
        return implode(' ', array_map(static fn (Scope $scope): string => $scope->value, $scopes));
    }
}
