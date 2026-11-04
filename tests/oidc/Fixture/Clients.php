<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Oidc\Application\Claims\PairwiseSubjectIdentifierResolver;
use Beffroi\Oidc\Domain\Ciba\DeliveryModeInterface;
use Beffroi\Oidc\Domain\Ciba\PingDelivery;
use Beffroi\Oidc\Domain\Ciba\PollDelivery;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Client\AccessTokenShapeInterface;
use Beffroi\Oidc\Domain\Client\Certificate\CertificateIdentityInterface;
use Beffroi\Oidc\Domain\Client\Certificate\SubjectDistinguishedName;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientPresentation;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;
use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Domain\Client\HashedClientSecret;
use Beffroi\Oidc\Domain\Client\InitiateLoginUri;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Domain\Client\RequestUri;
use Beffroi\Oidc\Domain\Client\RequestObject\AnyRegisteredAlgorithm;
use Beffroi\Oidc\Domain\Client\RequestObject\RequestObjectSigningInterface;
use Beffroi\Oidc\Domain\Resource\ResourceIndicator;
use Beffroi\Oidc\Domain\Client\ResponseFormat;
use Beffroi\Oidc\Domain\Client\SharedClientSecret;
use Beffroi\Oidc\Domain\Client\TokenExchange;
use Beffroi\Oidc\Domain\Exchange\MayAct;
use Beffroi\Oidc\Domain\Exchange\TokenTypeIdentifier;
use Beffroi\Oidc\Domain\Scope\Scope;

final class Clients
{
    public const string NOTIFICATION_ENDPOINT = 'https://terminal.example/ciba';

    public const string SECRET = 'a2b0c5d1e9f4a7b3c8d2e6f0a1b5c9d3e7f2a6b0c4d8e1f5a9b3c7d0e4f8a2b6';

    /**
     * RFC 8252 §7.3
     */
    public const string LOOPBACK_REDIRECT_URI = 'http://127.0.0.1/callback';

    public const string LOOPBACK_POST_LOGOUT_URI = 'http://127.0.0.1/after-logout';

    /**
     * RFC 8707 §2
     */
    public const string CALENDAR = 'https://cal.example.com/';

    public const string CONTACTS = 'https://contacts.example.com/';

    /**
     * @param list<GrantTypeName>|null $grantTypes
     * @param list<ResourceIndicator> $resources
     * @param list<string> $authorizationDetailsTypes
     * @param list<RedirectUri>|null $redirectUris
     */
    public static function confidential(
        Tenant $tenant,
        PasswordHash $secretHash,
        ?ClientAuthenticationMethodInterface $method = null,
        string $clientId = 'oidc-demo',
        bool $requiresPkce = true,
        ?AccessTokenShapeInterface $accessTokenShape = null,
        ?array $grantTypes = null,
        array $resources = [],
        array $authorizationDetailsTypes = [],
        ?array $redirectUris = null,
    ): Client {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('OIDC demo'),
                $method ?? Methods::clientSecretBasic(),
                true,
                $redirectUris ?? [new RedirectUri('https://demo.localhost/login/check')],
                $accessTokenShape ?? Shapes::jwt(),
                [new RedirectUri('https://demo.localhost/')],
                $grantTypes ?? [Grants::authorizationCode(), Grants::refreshToken()],
                new Scopes([new Scope('openid'), new Scope('profile'), new Scope('email')]),
                requiresPkce: $requiresPkce,
                resources: $resources,
                authorizationDetailsTypes: $authorizationDetailsTypes,
            ),
            new HashedClientSecret($secretHash),
        );
    }

    /**
     * RFC 6749 §4.4
     *
     * @param list<ResourceIndicator>|null $resources
     */
    public static function service(
        Tenant $tenant,
        PasswordHash $secretHash,
        string $clientId = 'batch',
        ?array $resources = null,
        ?Scopes $allowedScopes = null,
        ?AccessTokenShapeInterface $accessTokenShape = null,
    ): Client {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('Nightly batch'),
                Methods::clientSecretBasic(),
                true,
                [],
                $accessTokenShape ?? Shapes::jwt(),
                [],
                [Grants::clientCredentials()],
                $allowedScopes ?? new Scopes([new Scope('invoices.read'), new Scope('invoices.write')]),
                resources: $resources ?? self::resources(),
            ),
            new HashedClientSecret($secretHash),
        );
    }

    /**
     * RFC 8693 §2.1
     *
     * @param list<ResourceIndicator>|null $resources
     * @param list<TokenTypeIdentifier>|null $subjectTokenTypes
     */
    public static function gateway(
        Tenant $tenant,
        PasswordHash $secretHash,
        string $clientId = 'gateway',
        ?array $resources = null,
        ?Scopes $allowedScopes = null,
        bool $mayActForAUser = true,
        ?array $subjectTokenTypes = null,
        ?MayAct $mayAct = null,
        ?AccessTokenShapeInterface $accessTokenShape = null,
    ): Client {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('API gateway'),
                Methods::clientSecretBasic(),
                true,
                [],
                $accessTokenShape ?? Shapes::jwt(),
                [],
                [Grants::tokenExchange()],
                $allowedScopes ?? new Scopes([new Scope('invoices.read'), new Scope('invoices.write')]),
                resources: $resources ?? self::resources(),
                tokenExchange: new TokenExchange($subjectTokenTypes ?? [TokenTypeIdentifier::accessToken()], $mayActForAUser),
                mayAct: $mayAct,
            ),
            new HashedClientSecret($secretHash),
        );
    }

    /**
     * RFC 7523 §2.1
     *
     * @param list<ResourceIndicator>|null $resources
     */
    public static function presentingAssertions(
        Tenant $tenant,
        PasswordHash $secretHash,
        string $clientId = 'job-runner',
        ?array $resources = null,
        ?Scopes $allowedScopes = null,
        ?AccessTokenShapeInterface $accessTokenShape = null,
    ): Client {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('Nightly job runner'),
                Methods::clientSecretBasic(),
                true,
                [],
                $accessTokenShape ?? Shapes::jwt(),
                [],
                [Grants::jwtBearer()],
                $allowedScopes ?? new Scopes([new Scope('invoices.read'), new Scope('invoices.write')]),
                resources: $resources ?? self::resources(),
            ),
            new HashedClientSecret($secretHash),
        );
    }

    /**
     * RFC 8628 §3.1
     *
     * @param list<ResourceIndicator> $resources
     * @param list<GrantTypeName>|null $grantTypes
     */
    public static function appliance(
        Tenant $tenant,
        PasswordHash $secretHash,
        string $clientId = 'television',
        ?array $grantTypes = null,
        array $resources = [],
        ?Scopes $allowedScopes = null,
    ): Client {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('Television in the waiting room'),
                Methods::clientSecretBasic(),
                true,
                [],
                Shapes::jwt(),
                [],
                $grantTypes ?? [Grants::deviceCode(), Grants::refreshToken()],
                $allowedScopes ?? new Scopes([new Scope('openid'), new Scope('profile')]),
                requiresConsent: false,
                resources: $resources,
            ),
            new HashedClientSecret($secretHash),
        );
    }

    /**
     * CIBA Core §7
     *
     * @param list<ResourceIndicator> $resources
     * @param list<GrantTypeName>|null $grantTypes
     * @param non-empty-string|null $subjectType
     */
    public static function backchannel(
        Tenant $tenant,
        PasswordHash $secretHash,
        string $clientId = 'payment-terminal',
        ?DeliveryModeInterface $delivery = new PollDelivery(),
        ?ClientUri $notificationEndpoint = null,
        ?array $grantTypes = null,
        array $resources = [],
        ?Scopes $allowedScopes = null,
        ?ClientJwks $jwks = null,
        bool $requiresSignedRequestObject = false,
        ?string $jwksUri = null,
        ?string $sectorIdentifierUri = null,
        ?string $subjectType = null,
    ): Client {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('Payment terminal at the counter'),
                Methods::clientSecretBasic(),
                true,
                [],
                Shapes::jwt(),
                [],
                $grantTypes ?? [Grants::ciba(), Grants::refreshToken()],
                $allowedScopes ?? new Scopes([new Scope('openid'), new Scope('profile')]),
                requiresConsent: false,
                jwks: $jwks,
                requiresSignedRequestObject: $requiresSignedRequestObject,
                resources: $resources,
                backchannelTokenDeliveryMode: $delivery,
                backchannelClientNotificationEndpoint: $notificationEndpoint,
                jwksUri: $jwksUri === null ? null : new ClientUri($jwksUri),
                subjectType: $subjectType,
                sectorIdentifierUri: $sectorIdentifierUri === null ? null : new ClientUri($sectorIdentifierUri),
            ),
            new HashedClientSecret($secretHash),
        );
    }

    /**
     * CIBA Core §10.2
     */
    public static function pinged(Tenant $tenant, PasswordHash $secretHash, string $clientId = 'payment-terminal'): Client
    {
        return self::backchannel(
            $tenant,
            $secretHash,
            $clientId,
            new PingDelivery(),
            new ClientUri(self::NOTIFICATION_ENDPOINT),
        );
    }

    /**
     * RFC 8705 §3.4, FAPI 1.0 Advanced Final §5.2.2
     */
    public static function boundToItsCertificate(Tenant $tenant, string $clientId = 'bound-terminal'): Client
    {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('Payment terminal holding a certificate'),
                Methods::privateKeyJwt(),
                false,
                [],
                Shapes::jwt(),
                grantTypes: [Grants::ciba(), Grants::refreshToken()],
                allowedScopes: new Scopes([new Scope('openid'), new Scope('profile')]),
                requiresConsent: false,
                jwks: ClientAssertions::publishedKeys(),
                backchannelTokenDeliveryMode: new PollDelivery(),
                requiresCertificateBoundTokens: true,
            ),
        );
    }

    /**
     * RFC 9126 §6
     */
    public static function pushingOnly(Tenant $tenant, PasswordHash $secretHash, string $clientId = 'fapi-demo'): Client
    {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('FAPI demo'),
                Methods::clientSecretBasic(),
                true,
                [new RedirectUri('https://fapi.localhost/login/check')],
                Shapes::jwt(),
                [],
                [Grants::authorizationCode(), Grants::refreshToken()],
                new Scopes([new Scope('openid'), new Scope('profile'), new Scope('email')]),
                requiresPushedAuthorizationRequests: true,
            ),
            new HashedClientSecret($secretHash),
        );
    }

    /**
     * @param list<ResourceIndicator> $resources
     * @param list<GrantTypeName>|null $grantTypes
     * @param list<RedirectUri>|null $redirectUris
     * @param list<RedirectUri> $postLogoutRedirectUris
     */
    public static function public(
        Tenant $tenant,
        string $clientId = 'spa',
        array $resources = [],
        ?array $grantTypes = null,
        ?array $redirectUris = null,
        array $postLogoutRedirectUris = [],
        ?Scopes $allowedScopes = null,
    ): Client {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('Single page application'),
                Methods::none(),
                false,
                $redirectUris ?? [new RedirectUri('https://spa.example/callback')],
                Shapes::jwt(),
                $postLogoutRedirectUris,
                grantTypes: $grantTypes ?? [Grants::authorizationCode()],
                allowedScopes: $allowedScopes,
                resources: $resources,
            ),
        );
    }

    /**
     * OIDC Core §8.1
     */
    public static function pairwise(
        Tenant $tenant,
        string $clientId = 'pairwise-app',
        string $redirectUri = 'https://rp.example/callback',
        ?string $sectorIdentifierUri = null,
    ): Client {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('Application of a sector'),
                Methods::none(),
                false,
                [new RedirectUri($redirectUri)],
                Shapes::jwt(),
                grantTypes: [Grants::authorizationCode()],
                subjectType: PairwiseSubjectIdentifierResolver::SUBJECT_TYPE,
                sectorIdentifierUri: $sectorIdentifierUri === null ? null : new ClientUri($sectorIdentifierUri),
            ),
        );
    }

    /**
     * RFC 6749 §4.4, OIDC Core §8.1
     */
    public static function pairwiseService(Tenant $tenant, PasswordHash $secretHash): Client
    {
        return new Client(
            $tenant,
            new ClientRegistration(
                'pairwise-batch',
                new ClientPresentation('Batch of a sector'),
                Methods::clientSecretBasic(),
                true,
                [new RedirectUri('https://rp.example/callback')],
                Shapes::jwt(),
                [],
                [Grants::authorizationCode(), Grants::clientCredentials()],
                new Scopes([new Scope('invoices.read')]),
                resources: self::resources(),
                subjectType: PairwiseSubjectIdentifierResolver::SUBJECT_TYPE,
            ),
            new HashedClientSecret($secretHash),
        );
    }

    /**
     * OIDC Core §4
     *
     * @param list<RedirectUri>|null $redirectUris
     * @param non-empty-string|null $subjectType
     */
    public static function withThirdPartyInitiatedLogin(
        Tenant $tenant,
        string $clientId = 'launched-app',
        string $initiateLoginUri = 'https://rp.example/start',
        ?array $redirectUris = null,
        ?string $subjectType = null,
    ): Client {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('Application a third party starts'),
                Methods::none(),
                false,
                $redirectUris ?? [new RedirectUri('https://rp.example/callback')],
                Shapes::jwt(),
                grantTypes: [Grants::authorizationCode()],
                subjectType: $subjectType,
                initiateLoginUri: new InitiateLoginUri($initiateLoginUri),
            ),
        );
    }

    /**
     * RFC 8252 §8.3
     *
     * @param list<RedirectUri>|null $postLogoutRedirectUris
     */
    public static function native(Tenant $tenant, string $clientId = 'native-app', ?array $postLogoutRedirectUris = null): Client
    {
        return self::public(
            $tenant,
            $clientId,
            redirectUris: [new RedirectUri(self::LOOPBACK_REDIRECT_URI)],
            postLogoutRedirectUris: $postLogoutRedirectUris ?? [new RedirectUri(self::LOOPBACK_POST_LOGOUT_URI)],
        );
    }

    /**
     * @return list<ResourceIndicator>
     */
    public static function resources(): array
    {
        return [new ResourceIndicator(self::CALENDAR), new ResourceIndicator(self::CONTACTS)];
    }

    /**
     * RFC 9396 §11
     *
     * @return list<string>
     */
    public static function authorizationDetailsTypes(): array
    {
        return [AuthorizationDetailTypes::INVENTED];
    }

    /**
     * OIDC Core §9
     *
     * @param list<GrantTypeName>|null $grantTypes
     */
    public static function withKeys(
        Tenant $tenant,
        string $clientId = 'key-client',
        ?ClientJwks $jwks = null,
        ?ClientUri $jwksUri = null,
        ?ClientAuthenticationMethodInterface $method = null,
        ?array $grantTypes = null,
        ?string $sectorIdentifierUri = null,
    ): Client {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('Client with a key'),
                $method ?? Methods::privateKeyJwt(),
                false,
                [new RedirectUri('https://key.example/callback')],
                Shapes::jwt(),
                grantTypes: $grantTypes ?? [Grants::authorizationCode()],
                jwks: $jwksUri === null ? $jwks ?? ClientAssertions::publishedKeys() : null,
                jwksUri: $jwksUri,
                sectorIdentifierUri: $sectorIdentifierUri === null ? null : new ClientUri($sectorIdentifierUri),
            ),
        );
    }

    /**
     * OIDC Registration §2
     */
    public static function encryptedFor(
        Tenant $tenant,
        ?ResponseFormat $idToken = null,
        ?ResponseFormat $userInfo = null,
        ?ResponseFormat $authorizationResponse = null,
        string $clientId = 'encrypted-client',
    ): Client {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('Client that is written to in private'),
                Methods::clientSecretBasic(),
                true,
                [new RedirectUri('https://encrypted.example/callback')],
                Shapes::jwt(),
                [],
                [Grants::authorizationCode(), Grants::refreshToken()],
                new Scopes([new Scope('openid'), new Scope('profile'), new Scope('email')]),
                jwks: ClientEncryption::publishedKeys(),
                idToken: $idToken,
                authorizationResponse: $authorizationResponse,
                userInfo: $userInfo,
            ),
            new HashedClientSecret(new FakePasswordHasher()->hash(self::SECRET)),
        );
    }

    /**
     * RFC 9101 §4, §10.5
     *
     * @param list<RequestUri> $requestUris
     */
    public static function sendingRequestObjects(
        Tenant $tenant,
        ?RequestObjectSigningInterface $signing = null,
        array $requestUris = [],
        string $clientId = 'jar-client',
        bool $requiresSignedRequestObject = false,
    ): Client {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('Client that signs its requests'),
                Methods::clientSecretBasic(),
                true,
                [new RedirectUri('https://jar.example/callback')],
                Shapes::jwt(),
                [],
                [Grants::authorizationCode()],
                new Scopes([new Scope('openid'), new Scope('profile')]),
                jwks: ClientAssertions::publishedKeys(),
                requestObjectSigning: $signing ?? new AnyRegisteredAlgorithm(),
                requestUris: $requestUris,
                requiresSignedRequestObject: $requiresSignedRequestObject,
            ),
            new HashedClientSecret(new FakePasswordHasher()->hash(self::SECRET)),
        );
    }

    /**
     * OIDC Core §9
     */
    public static function withSharedSecret(Tenant $tenant, string $clientId = 'mac-client', string $secret = self::SECRET): Client
    {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('Client with a shared secret'),
                Methods::clientSecretJwt(),
                true,
                [new RedirectUri('https://mac.example/callback')],
                Shapes::jwt(),
            ),
            new SharedClientSecret($secret),
        );
    }

    /**
     * RFC 8705 §2.1
     */
    public static function withCertificateIdentity(
        Tenant $tenant,
        ?CertificateIdentityInterface $identity = null,
        string $clientId = 'mtls-client',
        ?AccessTokenShapeInterface $accessTokenShape = null,
    ): Client {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('Client with a certificate'),
                Methods::tlsClientAuth(),
                false,
                [new RedirectUri('https://mtls.example/callback')],
                $accessTokenShape ?? Shapes::jwt(),
                [],
                [Grants::authorizationCode(), Grants::refreshToken()],
                null,
                certificateIdentity: $identity ?? new SubjectDistinguishedName(Certificates::SUBJECT_DN),
            ),
        );
    }

    /**
     * RFC 8705 §2.2
     */
    public static function withPublishedCertificate(Tenant $tenant, ?ClientJwks $jwks = null, string $clientId = 'self-signed-client'): Client
    {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('Client with a self-signed certificate'),
                Methods::selfSignedTlsClientAuth(),
                false,
                [new RedirectUri('https://self-signed.example/callback')],
                Shapes::jwt(),
                [],
                [Grants::authorizationCode(), Grants::refreshToken()],
                null,
                jwks: $jwks ?? Certificates::publishedIn(Certificates::selfSigned()),
            ),
        );
    }

    /**
     * Front-Channel Logout 1.0 §3
     */
    public static function withFrontChannelLogout(
        Tenant $tenant,
        string $clientId = 'spa',
        string $logoutUri = 'https://spa.example/frontchannel-logout',
        bool $sessionRequired = false,
    ): Client {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('Single page application'),
                Methods::none(),
                false,
                [new RedirectUri('https://spa.example/callback')],
                Shapes::jwt(),
                frontChannelLogoutUri: new ClientUri($logoutUri),
                frontChannelLogoutSessionRequired: $sessionRequired,
            ),
        );
    }

    /**
     * Back-Channel Logout 1.0 §2.2
     */
    public static function withBackChannelLogout(Tenant $tenant, string $clientId = 'spa', string $logoutUri = 'https://spa.example/backchannel-logout'): Client
    {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('Single page application'),
                Methods::none(),
                false,
                [new RedirectUri('https://spa.example/callback')],
                Shapes::jwt(),
                backChannelLogoutUri: new ClientUri($logoutUri),
            ),
        );
    }
}
