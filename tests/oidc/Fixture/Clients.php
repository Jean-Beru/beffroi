<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Heidi\Core\Domain\Credential\PasswordHash;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Oidc\Domain\Ciba\DeliveryModeInterface;
use Heidi\Oidc\Domain\Ciba\PingDelivery;
use Heidi\Oidc\Domain\Ciba\PollDelivery;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Client\AccessTokenShapeInterface;
use Heidi\Oidc\Domain\Client\Certificate\CertificateIdentityInterface;
use Heidi\Oidc\Domain\Client\Certificate\SubjectDistinguishedName;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientRegistration;
use Heidi\Oidc\Domain\Client\GrantTypeName;
use Heidi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;
use Heidi\Oidc\Domain\Client\ClientJwks;
use Heidi\Oidc\Domain\Client\ClientUri;
use Heidi\Oidc\Domain\Client\HashedClientSecret;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Domain\Client\RequestObject\AnyRegisteredAlgorithm;
use Heidi\Oidc\Domain\Client\RequestObject\RequestObjectSigningInterface;
use Heidi\Oidc\Domain\Resource\ResourceIndicator;
use Heidi\Oidc\Domain\Client\ResponseFormat;
use Heidi\Oidc\Domain\Client\SharedClientSecret;
use Heidi\Oidc\Domain\Scope\Scope;

final class Clients
{
    /**
     * Where a client registered to be called back when a backchannel request has been answered.
     */
    public const string NOTIFICATION_ENDPOINT = 'https://terminal.example/ciba';

    public const string SECRET = 'a2b0c5d1e9f4a7b3c8d2e6f0a1b5c9d3e7f2a6b0c4d8e1f5a9b3c7d0e4f8a2b6';

    /**
     * Two resources a client may be registered for (RFC 8707 §2), as the examples of the RFC name them.
     */
    public const string CALENDAR = 'https://cal.example.com/';

    public const string CONTACTS = 'https://contacts.example.com/';

    /**
     * @param list<GrantTypeName>|null $grantTypes what this client registered for, the browser flow and its renewal unless the test says otherwise
     * @param list<ResourceIndicator> $resources what this client may ask a token for (RFC 8707 §2)
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
    ): Client {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                'OIDC demo',
                $method ?? Methods::clientSecretBasic(),
                true,
                [new RedirectUri('https://demo.localhost/login/check')],
                $accessTokenShape ?? Shapes::jwt(),
                [new RedirectUri('https://demo.localhost/')],
                $grantTypes ?? [Grants::authorizationCode(), Grants::refreshToken()],
                new Scopes([new Scope('openid'), new Scope('profile'), new Scope('email')]),
                requiresPkce: $requiresPkce,
                resources: $resources,
            ),
            new HashedClientSecret($secretHash),
        );
    }

    /**
     * A service acting for itself (RFC 6749 §4.4): a confidential client registered for the client
     * credentials grant, for the resources it asks its tokens for, and for no redirect URI, there being no
     * browser of anybody's to send anywhere.
     *
     * @param list<ResourceIndicator>|null $resources what this client may ask a token for, both fixtures unless the test says otherwise
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
                'Nightly batch',
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
     * An appliance with no browser and no keyboard (RFC 8628 §3.1): a client registered for the device grant
     * and for the renewal that goes with it, for no redirect URI, there being nothing of anybody's to send
     * anywhere, and for the scopes it shows its user on the approval page.
     *
     * @param list<ResourceIndicator> $resources what this client may ask a token for (RFC 8707 §2)
     * @param list<GrantTypeName>|null $grantTypes what this client registered for, the device grant and its renewal unless the test says otherwise
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
                'Television in the waiting room',
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
     * A client that asks for a user it names and waits for them to approve on a device of their own (CIBA
     * Core §7): registered for the backchannel grant and for the renewal that goes with it, for no
     * redirect URI, there being no browser of its own anywhere in the flow, and for a delivery mode,
     * without which it is not a client of this flow at all.
     *
     * @param list<ResourceIndicator> $resources what this client may ask a token for (RFC 8707 §2)
     * @param list<GrantTypeName>|null $grantTypes what this client registered for, the backchannel grant and its renewal unless the test says otherwise
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
    ): Client {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                'Payment terminal at the counter',
                Methods::clientSecretBasic(),
                true,
                [],
                Shapes::jwt(),
                [],
                $grantTypes ?? [Grants::ciba(), Grants::refreshToken()],
                $allowedScopes ?? new Scopes([new Scope('openid'), new Scope('profile')]),
                requiresConsent: false,
                jwks: $jwks,
                resources: $resources,
                backchannelTokenDeliveryMode: $delivery,
                backchannelClientNotificationEndpoint: $notificationEndpoint,
            ),
            new HashedClientSecret($secretHash),
        );
    }

    /**
     * The same client, registered for the mode where this provider calls it back (CIBA Core §10.2).
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
     * A client whose only way of starting an authorization request is to push it (RFC 9126 §6), which is
     * what FAPI 2.0 asks of one.
     */
    public static function pushingOnly(Tenant $tenant, PasswordHash $secretHash, string $clientId = 'fapi-demo'): Client
    {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                'FAPI demo',
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
     * @param list<ResourceIndicator> $resources what this client may ask a token for (RFC 8707 §2)
     * @param list<GrantTypeName>|null $grantTypes what this client registered for, the browser flow unless the test says otherwise
     */
    public static function public(Tenant $tenant, string $clientId = 'spa', array $resources = [], ?array $grantTypes = null): Client
    {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                'Single page application',
                Methods::none(),
                false,
                [new RedirectUri('https://spa.example/callback')],
                Shapes::jwt(),
                grantTypes: $grantTypes ?? [Grants::authorizationCode()],
                resources: $resources,
            ),
        );
    }

    /**
     * The two resources the fixtures name, for the tests that ask a token for one of them.
     *
     * @return list<ResourceIndicator>
     */
    public static function resources(): array
    {
        return [new ResourceIndicator(self::CALENDAR), new ResourceIndicator(self::CONTACTS)];
    }

    /**
     * A client that signs its assertions with a key of its own (OIDC Core §9, "private_key_jwt"),
     * publishing its JWK Set inline or behind a "jwks_uri".
     *
     * @param list<GrantTypeName>|null $grantTypes what this client registered for, the browser flow alone unless the test says otherwise
     */
    public static function withKeys(
        Tenant $tenant,
        string $clientId = 'key-client',
        ?ClientJwks $jwks = null,
        ?ClientUri $jwksUri = null,
        ?ClientAuthenticationMethodInterface $method = null,
        ?array $grantTypes = null,
    ): Client {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                'Client with a key',
                $method ?? Methods::privateKeyJwt(),
                false,
                [new RedirectUri('https://key.example/callback')],
                Shapes::jwt(),
                grantTypes: $grantTypes ?? [Grants::authorizationCode()],
                jwks: $jwksUri === null ? $jwks ?? ClientAssertions::publishedKeys() : null,
                jwksUri: $jwksUri,
            ),
        );
    }

    /**
     * A client that registered an encryption for what the provider hands it (OIDC Registration §2): it
     * publishes the key the document is addressed to, and receives the shapes given, signed then
     * encrypted. What it registers nothing for it receives as every other client does.
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
                'Client that is written to in private',
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
     * A client that sends its authorization requests in a JWT (RFC 9101 §4): it publishes the keys the
     * signature is verified against and registers, or not, the algorithm it signs with and the URLs its
     * objects are published at.
     *
     * @param list<ClientUri> $requestUris
     */
    public static function sendingRequestObjects(
        Tenant $tenant,
        ?RequestObjectSigningInterface $signing = null,
        array $requestUris = [],
        string $clientId = 'jar-client',
    ): Client {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                'Client that signs its requests',
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
            ),
            new HashedClientSecret(new FakePasswordHasher()->hash(self::SECRET)),
        );
    }

    /**
     * A client that signs its assertions with the secret it registered (OIDC Core §9,
     * "client_secret_jwt"), which the provider therefore holds in clear.
     */
    public static function withSharedSecret(Tenant $tenant, string $clientId = 'mac-client', string $secret = self::SECRET): Client
    {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                'Client with a shared secret',
                Methods::clientSecretJwt(),
                true,
                [new RedirectUri('https://mac.example/callback')],
                Shapes::jwt(),
            ),
            new SharedClientSecret($secret),
        );
    }

    /**
     * A client recognised by what its certificate says about it (RFC 8705 §2.1): it registers one of the
     * five values of §2.1.2, here the subject distinguished name unless the test names another.
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
                'Client with a certificate',
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
     * A client that publishes the certificate it signs itself (RFC 8705 §2.2), in its JWK Set.
     */
    public static function withPublishedCertificate(Tenant $tenant, ?ClientJwks $jwks = null, string $clientId = 'self-signed-client'): Client
    {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                'Client with a self-signed certificate',
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
     * A client the logout page loads in a frame when a session it signed in ends (Front-Channel Logout
     * 1.0 §3), which reads "iss" and "sid" only when it said so.
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
                'Single page application',
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
     * A client the provider tells when a session it signed in ends (Back-Channel Logout 1.0 §2.2).
     */
    public static function withBackChannelLogout(Tenant $tenant, string $clientId = 'spa', string $logoutUri = 'https://spa.example/backchannel-logout'): Client
    {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                'Single page application',
                Methods::none(),
                false,
                [new RedirectUri('https://spa.example/callback')],
                Shapes::jwt(),
                backChannelLogoutUri: new ClientUri($logoutUri),
            ),
        );
    }
}
