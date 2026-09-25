<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use function array_map;
use DateTimeImmutable;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Domain\Authorization\CodeChallenge;
use Heidi\Oidc\Domain\Authorization\CodeChallengeMethod;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Resource\ResourceIndicators;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\ConfirmationInterface;
use Heidi\Oidc\Domain\Token\KeyConfirmation;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Domain\Token\RefreshToken;
use Heidi\Oidc\Domain\Token\RefreshTokenFamily;
use Heidi\Oidc\Domain\Token\StoredClientAccessToken;
use Heidi\Oidc\Domain\Token\StoredUserAccessToken;
use Symfony\Component\Uid\Uuid;

final class Tokens
{
    /**
     * RFC 7636 appendix B: the verifier whose S256 challenge is Requests::CHALLENGE.
     */
    public const string CODE_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    /**
     * A code issued now for sixty seconds, for the first redirect URI of the client, bound to
     * Requests::CHALLENGE unless the request carried no challenge, with the authentication of the session.
     *
     */
    /**
     * @param list<string> $scopes
     */
    public static function code(
        string $code,
        Client $client,
        AuthenticationSession $session,
        DateTimeImmutable $issuedAt,
        array $scopes = ['openid'],
        ?string $nonce = 'n-0S6_WzA2Mj',
        ?ClaimsRequest $claims = null,
        bool $pkce = true,
        ?Uuid $grantId = null,
        ?KeyConfirmation $dpopKey = null,
        ?ResourceIndicators $resources = null,
    ): AuthorizationCode {
        return new AuthorizationCode(
            DrawnSecret::digestOf($code),
            $grantId ?? Uuid::v7(),
            $client,
            $session,
            $client->registration->redirectUris[0],
            new Scopes(array_map(static fn (string $scope): Scope => new Scope($scope), $scopes)),
            $resources,
            $nonce,
            $pkce ? new CodeChallenge(Requests::CHALLENGE, CodeChallengeMethod::S256) : null,
            $dpopKey,
            $claims,
            AuthenticationSnapshot::ofSession($session, $session->authenticationContextClass()),
            $issuedAt,
            $issuedAt->modify('+60 seconds'),
        );
    }

    /**
     * The record of an opaque access token issued now for ten minutes, under the hash of the value given,
     * with the authentication of the session.
     *
     */
    /**
     * @param list<string> $scopes
     */
    public static function storedAccessToken(
        string $value,
        Client $client,
        AuthenticationSession $session,
        DateTimeImmutable $issuedAt,
        ?Uuid $grantId = null,
        array $scopes = ['openid'],
        ?ClaimsRequest $claims = null,
        ?ResourceIndicators $resources = null,
    ): StoredUserAccessToken {
        return new StoredUserAccessToken(
            DrawnSecret::digestOf($value),
            $grantId ?? Uuid::v7(),
            $client,
            $session,
            new Scopes(array_map(static fn (string $scope): Scope => new Scope($scope), $scopes)),
            $resources,
            $claims,
            AuthenticationSnapshot::ofSession($session, $session->authenticationContextClass()),
            $issuedAt,
            $issuedAt->modify('+10 minutes'),
        );
    }

    /**
     * The record of an opaque access token a client holds for itself (RFC 6749 §4.4), issued now for ten
     * minutes, under the hash of the value given: no session, no authentication, nobody.
     *
     * @param list<string> $scopes
     */
    public static function storedClientAccessToken(
        string $value,
        Client $client,
        DateTimeImmutable $issuedAt,
        ?ResourceIndicators $resources = null,
        ?Uuid $grantId = null,
        array $scopes = ['invoices.read'],
    ): StoredClientAccessToken {
        return new StoredClientAccessToken(
            DrawnSecret::digestOf($value),
            $grantId ?? Uuid::v7(),
            $client,
            new Scopes(array_map(static fn (string $scope): Scope => new Scope($scope), $scopes)),
            $resources ?? ResourceIndicators::of([Clients::CALENDAR]),
            $issuedAt,
            $issuedAt->modify('+10 minutes'),
        );
    }

    /**
     * A family started now, from a code, for ninety days.
     */
    public static function family(DateTimeImmutable $startedAt, string $code = 'the-code', ?Uuid $grantId = null): RefreshTokenFamily
    {
        return new RefreshTokenFamily(Uuid::v7(), DrawnSecret::digestOf($code), $grantId ?? Uuid::v7(), $startedAt, $startedAt->modify('+90 days'));
    }

    /**
     * A refresh token issued now for thirty days, in the family given or a fresh one, with the
     * authentication of the session.
     *
     */
    /**
     * @param list<string> $scopes
     */
    public static function refreshToken(
        string $value,
        Client $client,
        AuthenticationSession $session,
        DateTimeImmutable $issuedAt,
        ?RefreshTokenFamily $family = null,
        array $scopes = ['openid'],
        ?ClaimsRequest $claims = null,
        ?ConfirmationInterface $confirmation = null,
        ?ResourceIndicators $resources = null,
    ): RefreshToken {
        $family ??= self::family($issuedAt);

        return new RefreshToken(
            DrawnSecret::digestOf($value),
            $family,
            $client,
            $session,
            new Scopes(array_map(static fn (string $scope): Scope => new Scope($scope), $scopes)),
            $resources,
            $claims,
            AuthenticationSnapshot::ofSession($session, $session->authenticationContextClass()),
            $issuedAt,
            $issuedAt->modify('+30 days') < $family->expiresAt ? $issuedAt->modify('+30 days') : $family->expiresAt,
            $confirmation,
        );
    }
}
