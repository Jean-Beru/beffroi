<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use function array_map;
use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Beffroi\Oidc\Domain\Authorization\AuthorizationCode;
use Beffroi\Oidc\Domain\Authorization\ClaimsRequest;
use Beffroi\Oidc\Domain\Authorization\CodeChallenge;
use Beffroi\Oidc\Domain\Authorization\Sha256CodeChallengeMethod;
use Beffroi\Oidc\Domain\Ciba\BackchannelAuthenticationRecord;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Device\DeviceAuthorizationRecord;
use Beffroi\Oidc\Domain\Device\UserCode;
use Beffroi\Oidc\Domain\Exchange\Actor;
use Beffroi\Oidc\Domain\Exchange\MayAct;
use Beffroi\Oidc\Domain\Exchange\PresentedToken;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Token\AccessToken;
use Beffroi\Oidc\Domain\Token\AuthorizationInterface;
use Beffroi\Oidc\Domain\Token\ConfirmationInterface;
use Beffroi\Oidc\Domain\Token\KeyConfirmation;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Domain\Token\RefreshToken;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Token\RefreshTokenFamily;
use Beffroi\Oidc\Domain\Token\StoredClientAccessToken;
use Beffroi\Oidc\Domain\Token\StoredSubjectAccessToken;
use Beffroi\Oidc\Domain\Token\StoredUserAccessToken;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Port\AccessTokenIssuerInterface;
use Beffroi\Oidc\Domain\Token\TokenAudience;
use Beffroi\Oidc\Domain\Token\TokenSignIn;
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
        ?AuthorizationDetails $authorizationDetails = null,
    ): AuthorizationCode {
        return new AuthorizationCode(
            DrawnSecret::digestOf($code),
            $grantId ?? Uuid::v7(),
            $client,
            $session,
            $client->registration->redirectUris[0],
            new Scopes(array_map(static fn (string $scope): Scope => new Scope($scope), $scopes)),
            $resources,
            $authorizationDetails,
            $nonce,
            $pkce ? new CodeChallenge(Requests::CHALLENGE, new Sha256CodeChallengeMethod()) : null,
            $dpopKey,
            $claims,
            AuthenticationSnapshot::ofSession($session, $session->authenticationContextClass()),
            $issuedAt,
            $issuedAt->modify('+60 seconds'),
        );
    }

    /**
     * A device authorization request already approved by the session given, the grant a token of that flow
     * descends from (RFC 8628 §3.3).
     *
     * @param list<string> $scopes
     */
    public static function approvedDeviceRecord(
        Client $client,
        AuthenticationSession $session,
        DateTimeImmutable $issuedAt,
        array $scopes = ['openid'],
        ?Uuid $grantId = null,
    ): DeviceAuthorizationRecord {
        $record = new DeviceAuthorizationRecord(
            DrawnSecret::digestOf('the-device-code'),
            UserCode::hashOf('BCDFGHJK'),
            $grantId ?? Uuid::v7(),
            $client,
            new Scopes(array_map(static fn (string $scope): Scope => new Scope($scope), $scopes)),
            null,
            Fixtures::context($issuedAt),
            $issuedAt,
            $issuedAt->modify('+600 seconds'),
        );
        $record->approve($session, AuthenticationSnapshot::ofSession($session, $session->authenticationContextClass()), $issuedAt);

        return $record;
    }

    /**
     * A backchannel authentication request already approved by the session given, the grant a token of that
     * flow descends from (CIBA Core §7.1).
     *
     * @param list<string> $scopes
     */
    public static function approvedBackchannelRecord(
        Client $client,
        AuthenticationSession $session,
        DateTimeImmutable $issuedAt,
        array $scopes = ['openid'],
        ?Uuid $grantId = null,
    ): BackchannelAuthenticationRecord {
        $record = new BackchannelAuthenticationRecord(
            DrawnSecret::digestOf('the-auth-req-id'),
            $grantId ?? Uuid::v7(),
            $client,
            $session->user,
            new Scopes(array_map(static fn (string $scope): Scope => new Scope($scope), $scopes)),
            null,
            null,
            [],
            null,
            null,
            Fixtures::context($issuedAt),
            $issuedAt,
            $issuedAt->modify('+600 seconds'),
        );
        $record->approve($session, AuthenticationSnapshot::ofSession($session, $session->authenticationContextClass()), $issuedAt);

        return $record;
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
        ?AuthorizationDetails $authorizationDetails = null,
    ): StoredUserAccessToken {
        return new StoredUserAccessToken(
            DrawnSecret::digestOf($value),
            $grantId ?? Uuid::v7(),
            $client,
            $session,
            new Scopes(array_map(static fn (string $scope): Scope => new Scope($scope), $scopes)),
            $resources,
            $authorizationDetails,
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
     * The record of an opaque access token whose subject was named by what the client presented
     * (RFC 8693 §2.1, RFC 7523 §2.1), issued now for ten minutes, under the hash of the value given.
     *
     * @param list<string> $scopes
     */
    public static function storedSubjectAccessToken(
        string $value,
        Client $client,
        Subject $subject,
        DateTimeImmutable $issuedAt,
        ?ResourceIndicators $resources = null,
        ?Uuid $grantId = null,
        array $scopes = ['invoices.read'],
        ?AuthenticationSession $session = null,
        ?Actor $actor = null,
        ?Subject $person = null,
    ): StoredSubjectAccessToken {
        return new StoredSubjectAccessToken(
            DrawnSecret::digestOf($value),
            $grantId ?? Uuid::v7(),
            $client,
            $subject,
            // what the exchange resolved of the presented token: the person who signed in for it, and
            // nobody when nobody did (issue #593)
            $person ?? $session?->user->subject,
            new Scopes(array_map(static fn (string $scope): Scope => new Scope($scope), $scopes)),
            $resources ?? ResourceIndicators::of([Clients::CALENDAR]),
            $session?->id,
            $session === null ? null : AuthenticationSnapshot::ofSession($session, $session->authenticationContextClass()),
            $actor,
            $issuedAt,
            $issuedAt->modify('+10 minutes'),
        );
    }

    /**
     * What the exchange reads of the token a request presents (RFC 8693 §2.1), about a user when a session is
     * given and about the client itself otherwise (RFC 6749 §4.4).
     *
     * @param list<string> $scopes
     * @param list<string>|null $audience who the presented token is addressed to, the calendar unless the test says otherwise
     */
    public static function presented(
        Client $client,
        Subject $subject,
        ?AuthenticationSession $session = null,
        array $scopes = ['invoices.read', 'invoices.write'],
        ?array $audience = null,
        ?Uuid $grantId = null,
        ?Actor $actor = null,
        ?MayAct $mayAct = null,
    ): PresentedToken {
        return new PresentedToken(
            $subject,
            $client,
            new Scopes(array_map(static fn (string $scope): Scope => new Scope($scope), $scopes)),
            new TokenAudience($audience ?? [Clients::CALENDAR]),
            $grantId ?? Uuid::v7(),
            $session === null ? null : new TokenSignIn($session->id, AuthenticationSnapshot::ofSession($session, $session->authenticationContextClass())),
            $actor,
            $mayAct,
            // what the type that read the token found behind it (issue #588): the user of the session it
            // descends from, there being nobody behind a token a client holds for itself
            $session?->user->subject,
        );
    }

    /**
     * The access token that issuer writes for that authorization, addressed and struck at once, as a caller that
     * spends nothing on the way to it does both: what a test asks for when it needs a token, and not the order
     * of the two steps.
     */
    public static function accessToken(AccessTokenIssuerInterface $issuer, AuthorizationInterface $authorization, DateTimeImmutable $now): AccessToken
    {
        return $issuer->issue($authorization, $issuer->addressFor($authorization), $now);
    }

    /**
     * A family started now, from a code, for ninety days.
     */
    public static function family(DateTimeImmutable $startedAt, Tenant $tenant, string $code = 'the-code', ?Uuid $grantId = null): RefreshTokenFamily
    {
        return new RefreshTokenFamily(Uuid::v7(), $tenant, DrawnSecret::digestOf($code), $grantId ?? Uuid::v7(), $startedAt, $startedAt->modify('+90 days'));
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
        ?AuthorizationDetails $authorizationDetails = null,
    ): RefreshToken {
        $family ??= self::family($issuedAt, $client->tenant);

        return new RefreshToken(
            DrawnSecret::digestOf($value),
            $family,
            $client,
            $session,
            new Scopes(array_map(static fn (string $scope): Scope => new Scope($scope), $scopes)),
            $resources,
            $authorizationDetails,
            $claims,
            AuthenticationSnapshot::ofSession($session, $session->authenticationContextClass()),
            $issuedAt,
            $issuedAt->modify('+30 days') < $family->expiresAt ? $issuedAt->modify('+30 days') : $family->expiresAt,
            $confirmation,
        );
    }
}
