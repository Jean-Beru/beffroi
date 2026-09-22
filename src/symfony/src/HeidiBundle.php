<?php

declare(strict_types=1);

namespace Heidi\Bundle;

use function array_column;
use DateInterval;
use function dirname;
use Heidi\Bundle\Client\ClientJwksCache;
use Heidi\Bundle\Client\ClientJwksFetcher;
use Heidi\Bundle\Client\RequestObjectFetcher;
use Heidi\Bundle\Doctrine\Type\AddressType;
use Heidi\Bundle\Doctrine\Type\AuthenticationContextPolicyType;
use Heidi\Bundle\Doctrine\Type\AuthenticationProofsType;
use Heidi\Bundle\Doctrine\Type\BackupCodesType;
use Heidi\Bundle\Doctrine\Type\BytesType;
use Heidi\Bundle\Doctrine\Type\ClaimsRequestType;
use Heidi\Bundle\Doctrine\Type\CodeChallengeType;
use Heidi\Bundle\Doctrine\Type\ConfirmationType;
use Heidi\Bundle\Doctrine\Type\DeviceType;
use Heidi\Bundle\Doctrine\Type\EmailAddressType;
use Heidi\Bundle\Doctrine\Type\GeoLocationType;
use Heidi\Bundle\Doctrine\Type\IssuerType;
use Heidi\Bundle\Doctrine\Type\PasskeyUserHandleType;
use Heidi\Bundle\Doctrine\Type\RedirectUriType;
use Heidi\Bundle\Doctrine\Type\ScopesType;
use Heidi\Bundle\Doctrine\Type\SubjectType;
use Heidi\Bundle\Http\LogoutTokenSender;
use Heidi\Bundle\Key\FileSigningKeyRepository;
use Heidi\Bundle\Key\StagingDelay;
use Heidi\Bundle\Plane\Plane;
use Heidi\Bundle\Routing\RouterEndpointLocator;
use Heidi\Bundle\Security\CorePasswordHasher;
use Heidi\Bundle\Security\RateLimitedAttempts;
use Heidi\Bundle\Security\SecurityUser;
use Heidi\Bundle\Tenant\TenantFactory;
use Heidi\Bundle\Webauthn\FileMetadataBlobStore;
use Heidi\Core\Application\Key\SigningKeyRotator;
use Heidi\Core\Bridge\KeyManagement\EnvelopeKeySealer;
use Heidi\Core\Bridge\KeyManagement\EnvelopeSecretSealer;
use Heidi\Core\Domain\Session\AuthenticationContextClass;
use Heidi\Core\Domain\Session\AuthenticationPredicate;
use Heidi\Oidc\Application\Authorization\AuthorizationHandler;
use Heidi\Oidc\Application\Authorization\RequestObjectValidator;
use Heidi\Oidc\Application\Client\ClientAssertionValidator;
use Heidi\Oidc\Application\Client\ClientKeySetProvider;
use Heidi\Oidc\Application\Discovery\JwksHandler;
use Heidi\Oidc\Application\PushedAuthorization\PushedAuthorizationHandler;
use Heidi\Oidc\Application\Token\AuthorizationCodeGrant;
use Heidi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Heidi\Oidc\Application\Token\JwtIdTokenIssuer;
use Heidi\Oidc\Application\Token\OpaqueAccessTokenIssuer;
use Heidi\Oidc\Application\Token\TokenIssuer;
use Heidi\Oidc\Bridge\Configuration\ConfigurationClientRepository;
use Heidi\Oidc\Domain\Client\AccessTokenFormat;
use Heidi\Oidc\Domain\Client\Certificate\CertificateIdentities;
use Heidi\Oidc\Domain\Client\GrantType;
use function is_array;
use function is_float;
use function is_int;
use function is_string;
use function sprintf;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Kernel\AbstractBundle;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\inline_service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use Symfony\Component\KeyManagement\EncrypterInterface;
use Symfony\Component\KeyManagement\EnvelopeEncrypter;

/**
 * The configuration of architecture §5.1, and nothing that decision 0006 forbids: no "insecure_*" key, no
 * compatibility switch.
 */
final class HeidiBundle extends AbstractBundle
{
    /**
     * RFC 6749 §4.1.2, the recommendation made a bound.
     */
    public const int MAX_AUTHORIZATION_CODE_TTL = 600;

    /**
     * RFC 9126 §2.2: "typically be relatively short (e.g., between 5 and 600 seconds)", the upper end
     * made a bound; a reference the provider holds is a request nobody has consented to yet.
     */
    public const int MAX_REQUEST_URI_TTL = 600;

    /**
     * Seconds one attempt at delivering a logout token is given (Back-Channel Logout 1.0 §2.5).
     */
    public const float DEFAULT_BACK_CHANNEL_LOGOUT_TIMEOUT = 5.0;

    /**
     * RFC 7523 §3: how far ahead of the request the "exp" of a client assertion may be. Five minutes is
     * what the field sends; an assertion is minted for one request, not kept.
     */
    public const int DEFAULT_ASSERTION_MAX_LIFETIME = 300;

    /**
     * What is allowed of the clock of a client, both ways.
     */
    public const int DEFAULT_ASSERTION_LEEWAY = 30;

    /**
     * Seconds one read of a "jwks_uri" is given, connection included: an endpoint authenticating a client
     * is waiting on it.
     */
    public const float DEFAULT_JWKS_TIMEOUT = 3.0;

    /**
     * Bytes a "jwks_uri" may answer; a JWK Set of a client holds a handful of public keys.
     */
    public const int DEFAULT_JWKS_MAX_SIZE = 65536;

    /**
     * How long the keys read back from a "jwks_uri" are kept.
     */
    public const int DEFAULT_JWKS_TTL = 86400;

    /**
     * How often an unknown "kid" may cost a read of a "jwks_uri", the symmetric of the cooldown of
     * Symfony's own client (spike 2).
     */
    public const int DEFAULT_JWKS_REFETCH_COOLDOWN = 300;

    /**
     * RFC 9101 §4: how long a request object may stand, from its "nbf". One hour is what FAPI 2.0
     * Message Signing allows; an object is a request made now, not an authorization kept for a day.
     */
    public const int DEFAULT_REQUEST_OBJECT_MAX_LIFETIME = 3600;

    /**
     * What is allowed of the clock of a client, both ways.
     */
    public const int DEFAULT_REQUEST_OBJECT_LEEWAY = 30;

    /**
     * Seconds one read of a "request_uri" is given, connection included: the browser of a user is
     * waiting on it.
     */
    public const float DEFAULT_REQUEST_OBJECT_TIMEOUT = 3.0;

    /**
     * Bytes a "request_uri" may answer; a request object carries the parameters of one request.
     */
    public const int DEFAULT_REQUEST_OBJECT_MAX_SIZE = 65536;

    /**
     * Restated from the module: the configuration tree cannot tell an absent list from an empty one.
     */
    public const array DEFAULT_GRANT_TYPES = [GrantType::AuthorizationCode->value, GrantType::RefreshToken->value];

    public const array DEFAULT_ALLOWED_SCOPES = ['openid', 'profile', 'email'];

    /**
     * The default policy of decision 0010, restated for the same reason; a test checks it equals the core's.
     */
    public const array DEFAULT_AUTHENTICATION_CLASSES = [
        AuthenticationContextClass::PHISHING_RESISTANT_HARDWARE => AuthenticationPredicate::PhishingResistantHardware->value,
        AuthenticationContextClass::PHISHING_RESISTANT => AuthenticationPredicate::PhishingResistant->value,
        AuthenticationContextClass::TWO_FACTORS => AuthenticationPredicate::TwoFactors->value,
        AuthenticationContextClass::SINGLE_FACTOR => AuthenticationPredicate::SingleFactor->value,
    ];

    protected string $extensionAlias = 'heidi';

    public function configure(DefinitionConfigurator $definition): void
    {
        $definition->rootNode()
            ->children()
            ->arrayNode('tenant')
            ->info('The one tenant of this deployment: the key is already a tenant, a table comes later.')
            ->isRequired()
            ->children()
            ->scalarNode('issuer')
            ->info('Issuer identifier (OIDC Discovery §3): an absolute HTTPS URL, no query, no fragment, no trailing slash; plain HTTP on a loopback host only.')
            ->isRequired()
            ->cannotBeEmpty()
            ->end()
            ->scalarNode('slug')
            ->info('Stable name of the tenant, from which its identifier is derived; renaming it is creating another tenant.')
            ->defaultValue('default')
            ->cannotBeEmpty()
            ->end()
            ->scalarNode('name')
            ->info('Display name; the host of the issuer when absent.')
            ->defaultNull()
            ->end()
            ->arrayNode('authentication_classes')
            ->info('The "acr" vocabulary of the tenant (decision 0010): class names, in the order a session is answered in, each on a predicate of the provider; the default policy ("phrh", "phr", "2", "1") when absent.')
            ->useAttributeAsKey('name')
            ->normalizeKeys(false)
            ->defaultValue(self::DEFAULT_AUTHENTICATION_CLASSES)
            ->enumPrototype()
            ->values(array_column(AuthenticationPredicate::cases(), 'value'))
            ->end()
            ->end()
            ->end()
            ->end()
            ->arrayNode('keys')
            ->info('Where the signing keys live: sealed by the KMS named here, stored as files until a table takes over (architecture §3.3).')
            ->isRequired()
            ->children()
            ->scalarNode('kms')
            ->info('DSN of the KMS that seals the private keys ("sodium://..." locally, a Vault or cloud scheme in production); the KMS keeps, it never signs.')
            ->isRequired()
            ->cannotBeEmpty()
            ->end()
            ->scalarNode('key_id')
            ->info('The key of that KMS the signing keys are sealed under (backend-specific: the id of a sodium key, a Vault transit key name, an ARN); "{tenant}" stands for the slug of the tenant, one master key each.')
            ->isRequired()
            ->cannotBeEmpty()
            ->end()
            ->scalarNode('storage')
            ->info('Directory of the sealed signing keys, one file per key and per tenant.')
            ->defaultValue('%kernel.project_dir%/var/keys')
            ->cannotBeEmpty()
            ->end()
            ->integerNode('jwks_max_age')
            ->info('How long a relying party may cache the JWK Set, in seconds (RFC 7517 §5, architecture §4.8); the staging window of a rotation derives from it, so that the two cannot drift apart (§3.3).')
            ->defaultValue(JwksHandler::DEFAULT_MAX_AGE)
            ->min(0)
            ->end()
            ->integerNode('staging_delay')
            ->info('How long a new key is published before it signs, in seconds (architecture §3.3, §9); unless set, jwks_max_age plus the 60 s refetch cooldown of oidc_login: the max-age is what a relying party with a warm cache needs to see the new key, the cooldown what one served by a shared HTTP cache needs to refetch it.')
            ->defaultNull()
            ->min(0)
            ->end()
            ->end()
            ->end()
            ->arrayNode('webauthn')
            ->info('What the passkey ceremonies read besides the tenant (architecture §3.4).')
            ->addDefaultsIfNotSet()
            ->children()
            ->scalarNode('metadata_storage')
            ->info('Directory of the FIDO metadata the ceremonies check an attestation against: the documents "heidi:webauthn:mds-refresh" verified and "heidi:webauthn:mds-import" stored, next to the keys; empty until one of them ran, which the enrolment of the provider does not need.')
            ->defaultValue('%kernel.project_dir%/var/webauthn')
            ->cannotBeEmpty()
            ->end()
            ->end()
            ->end()
            ->arrayNode('mutual_tls')
            ->info('Where a client that presents a certificate reaches the endpoints (RFC 8705 §5). The certificate itself comes from the edge, which is infrastructure and not configuration (docs/mtls-at-the-edge.md); what a deployment says here is the host its listener asks for one on.')
            ->addDefaultsIfNotSet()
            ->children()
            ->scalarNode('origin')
            ->info('Scheme and authority of that host, without a path ("https://mtls.op.example"). The endpoints are announced under it in "mtls_endpoint_aliases", with the paths they are served at. Absent, the document announces no alias and a client authenticating by mutual TLS reaches the ordinary endpoints, which is what a deployment serving one host does.')
            ->defaultNull()
            ->end()
            ->end()
            ->end()
            ->arrayNode('tokens')
            ->info('Lifetimes in seconds. The defaults are the choices of architecture §9.')
            ->addDefaultsIfNotSet()
            ->children()
            ->integerNode('authorization_code_ttl')
            ->info('RFC 6749 §4.1.2 recommends ten minutes at most; sixty seconds bound the injection window.')
            ->defaultValue(60)
            ->min(1)
            ->max(self::MAX_AUTHORIZATION_CODE_TTL)
            ->end()
            ->integerNode('access_token_ttl')
            ->info('Both shapes of access token (architecture §4.6): the self-contained one cannot be revoked, and a short lifetime bounds the exposure; the opaque one gets the same, a revocation is a facility and not a reason to live longer.')
            ->defaultValue(600)
            ->min(1)
            ->end()
            ->integerNode('id_token_ttl')
            ->defaultValue(600)
            ->min(1)
            ->end()
            ->integerNode('request_uri_ttl')
            ->info('Seconds a request_uri answered by the pushed authorization request endpoint lives (RFC 9126 §2.2); sixty is the example of the specification, and the browser is sent the moment the client holds the reference.')
            ->defaultValue(60)
            ->min(1)
            ->max(self::MAX_REQUEST_URI_TTL)
            ->end()
            ->integerNode('refresh_token_ttl')
            ->info('Sliding lifetime of a refresh token, renewed at each rotation.')
            ->defaultValue(2592000)
            ->min(1)
            ->end()
            ->integerNode('refresh_token_absolute_ttl')
            ->info('Lifetime of a refresh token family from the authorization that started it; no rotation extends it.')
            ->defaultValue(7776000)
            ->min(1)
            ->end()
            ->end()
            ->validate()
            ->ifTrue(static fn (array $tokens): bool => is_int($tokens['refresh_token_ttl']) && is_int($tokens['refresh_token_absolute_ttl']) && $tokens['refresh_token_ttl'] > $tokens['refresh_token_absolute_ttl'])
            ->thenInvalid('The sliding lifetime of a refresh token (refresh_token_ttl) cannot exceed the absolute lifetime of its family (refresh_token_absolute_ttl).')
            ->end()
            ->end()
            ->arrayNode('back_channel_logout')
            ->info('How a logout token reaches a client that registered a backchannel_logout_uri (Back-Channel Logout 1.0 §2.5). How many times a send is tried again is the retry policy of the transport the message is routed to, in the application.')
            ->addDefaultsIfNotSet()
            ->children()
            ->floatNode('timeout')
            ->info('Seconds one attempt is given, connection included. A relying party that hangs must not hold a worker; five seconds is long for a request that reads nothing back, and a client that needs longer is a client that is down, which the retries cover.')
            ->defaultValue(self::DEFAULT_BACK_CHANNEL_LOGOUT_TIMEOUT)
            ->min(0.1)
            ->end()
            ->end()
            ->end()
            ->arrayNode('client_authentication')
            ->info('How a client proves who it is at the endpoints that authenticate one (RFC 6749 §2.3, OIDC Core §9). Which methods the provider takes is the wiring, not this: a method is a tagged service, and what is tagged is what is announced.')
            ->addDefaultsIfNotSet()
            ->children()
            ->integerNode('assertion_max_lifetime')
            ->info('Seconds ahead of the request the "exp" of a client assertion may be (RFC 7523 §3). An assertion is minted for one request; a long one is a bearer token nobody watches.')
            ->defaultValue(self::DEFAULT_ASSERTION_MAX_LIFETIME)
            ->min(1)
            ->end()
            ->integerNode('assertion_leeway')
            ->info('Seconds allowed of the clock of a client, both ways.')
            ->defaultValue(self::DEFAULT_ASSERTION_LEEWAY)
            ->min(0)
            ->end()
            ->floatNode('jwks_timeout')
            ->info('Seconds one read of a jwks_uri is given, connection included. A client that hangs must not hold a worker: an endpoint authenticating it is waiting.')
            ->defaultValue(self::DEFAULT_JWKS_TIMEOUT)
            ->min(0.1)
            ->end()
            ->integerNode('jwks_max_size')
            ->info('Bytes a jwks_uri may answer before the read stops; a JWK Set of a client holds a handful of public keys.')
            ->defaultValue(self::DEFAULT_JWKS_MAX_SIZE)
            ->min(1)
            ->end()
            ->integerNode('jwks_ttl')
            ->info('Seconds the keys read back from a jwks_uri are kept in the pool the workers share.')
            ->defaultValue(self::DEFAULT_JWKS_TTL)
            ->min(1)
            ->end()
            ->integerNode('jwks_refetch_cooldown')
            ->info('Seconds between two reads of the same jwks_uri when an assertion names a "kid" the kept set does not hold. A client that rotates a key is followed within one request; a client that signs with a key it never published cannot make the provider call it on every request.')
            ->defaultValue(self::DEFAULT_JWKS_REFETCH_COOLDOWN)
            ->min(0)
            ->end()
            ->end()
            ->end()
            ->arrayNode('request_objects')
            ->info('How a request the client carried in a JWT is read (RFC 9101 §4, OIDC Core §6). Which algorithm verifies it is the wiring and the registration of the client, not this; an unsigned object is read from a client that registered "none" and from no other.')
            ->addDefaultsIfNotSet()
            ->children()
            ->integerNode('max_lifetime')
            ->info('Seconds a request object may stand, from its "nbf" (RFC 9101 §4). An object is a request made now; a long one is an authorization a client keeps.')
            ->defaultValue(self::DEFAULT_REQUEST_OBJECT_MAX_LIFETIME)
            ->min(1)
            ->end()
            ->integerNode('leeway')
            ->info('Seconds allowed of the clock of a client, both ways.')
            ->defaultValue(self::DEFAULT_REQUEST_OBJECT_LEEWAY)
            ->min(0)
            ->end()
            ->floatNode('timeout')
            ->info('Seconds one read of a request_uri is given, connection included. The browser of a user is waiting on it; no redirect is followed and only a URL the client registered is ever read.')
            ->defaultValue(self::DEFAULT_REQUEST_OBJECT_TIMEOUT)
            ->min(0.1)
            ->end()
            ->integerNode('max_size')
            ->info('Bytes a request_uri may answer before the read stops; a request object carries the parameters of one request.')
            ->defaultValue(self::DEFAULT_REQUEST_OBJECT_MAX_SIZE)
            ->min(1)
            ->end()
            ->end()
            ->end()
            ->arrayNode('clients')
            ->info('The clients of the tenant, keyed by client identifier. A secret is hashed when the client is loaded and never kept in clear, unless the method it registered has to compute a MAC with it (client_secret_jwt).')
            ->useAttributeAsKey('client_id')
            ->normalizeKeys(false)
            ->arrayPrototype()
            ->children()
            ->scalarNode('name')
            ->info('Shown on the consent page; the client identifier when absent.')
            ->defaultNull()
            ->end()
            ->scalarNode('secret')
            ->info('At least 32 visible ASCII characters, generated, never chosen; absent for a public client.')
            ->defaultNull()
            ->end()
            ->arrayNode('redirect_uris')
            ->info('Compared byte for byte with the redirect_uri of a request (RFC 6749 §3.1.2.3); HTTPS, or plain HTTP on a loopback host.')
            ->scalarPrototype()
            ->end()
            ->end()
            ->arrayNode('post_logout_redirect_uris')
            ->info('Compared byte for byte with the post_logout_redirect_uri of a logout request (RP-Initiated Logout §3).')
            ->scalarPrototype()
            ->end()
            ->end()
            ->arrayNode('grant_types')
            ->defaultValue(self::DEFAULT_GRANT_TYPES)
            ->enumPrototype()
            ->values(array_column(GrantType::cases(), 'value'))->end()
            ->end()
            ->arrayNode('allowed_scopes')
            ->defaultValue(self::DEFAULT_ALLOWED_SCOPES)
            ->scalarPrototype()
            ->end()
            ->end()
            ->scalarNode('token_endpoint_auth_method')
            ->info('How this client authenticates at the endpoints that authenticate a client (OIDC Core §9), among the methods the provider is wired with; left out, it takes the first wired one. A name nothing authenticates with fails at boot.')
            ->defaultNull()
            ->end()
            ->booleanNode('requires_consent')
            ->info('Consent is the rule; a first-party application is the named exception.')
            ->defaultTrue()
            ->end()
            ->booleanNode('requires_pkce')
            ->info('PKCE S256 is the rule; a confidential client that cannot send a code_challenge is the named exception of decision 0008, refused for a public client. A challenge the client sends is verified all the same.')
            ->defaultTrue()
            ->end()
            ->booleanNode('require_pushed_authorization_requests')
            ->info('The only way this client starts an authorization request is by pushing it (RFC 9126 §6), which is what FAPI 2.0 asks of one; an ordinary request from it is refused on a page before its redirect URI is even read. Per client, nothing global: the document announces the requirement when every registered client carries it.')
            ->defaultFalse()
            ->end()
            ->scalarNode('id_token_signed_response_alg')
            ->info('The JWS algorithm the ID tokens and the logout tokens of this client are signed with (OIDC Registration §2), among those the provider is wired with; left out, the provider signs them with its default. A name nothing signs under fails at boot.')
            ->defaultNull()
            ->end()
            ->enumNode('access_token_format')
            ->info('The shape of the access tokens: "jwt" (RFC 9068, verified offline against the JWK Set) or "opaque" (a reference the resource server introspects, RFC 7662, revocable at once). Per client, nothing global.')
            ->values(array_column(AccessTokenFormat::cases(), 'value'))
            ->defaultValue(AccessTokenFormat::Jwt->value)
            ->end()
            ->scalarNode('backchannel_logout_uri')
            ->info('Where the provider posts a logout token when a session this client signed in ends (Back-Channel Logout 1.0 §2.2); HTTPS, or plain HTTP on a loopback host. Absent for a client the provider does not tell.')
            ->defaultNull()
            ->end()
            ->booleanNode('backchannel_logout_session_required')
            ->info('The client reads the "sid" of the logout token to know which session ended (Back-Channel Logout 1.0 §2.2); it needs a backchannel_logout_uri. The provider sends "sid" either way.')
            ->defaultFalse()
            ->end()
            ->scalarNode('frontchannel_logout_uri')
            ->info('Loaded in a frame of the logout page when a session this client signed in ends (Front-Channel Logout 1.0 §3); HTTPS, or plain HTTP on a loopback host. Absent for a client the page does not load. It reaches the client only if the browser sends that client its cookies.')
            ->defaultNull()
            ->end()
            ->booleanNode('frontchannel_logout_session_required')
            ->info('The client reads "iss" and "sid" on its logout URI to know which session ended (Front-Channel Logout 1.0 §2); it needs a frontchannel_logout_uri. The two parameters are added for this client only, §2 making them conditional.')
            ->defaultFalse()
            ->end()
            ->variableNode('jwks')
            ->info('The JWK Set of the client, inline (RFC 7591 §2): public keys only, and exclusive with jwks_uri. A client that authenticates with private_key_jwt publishes one of the two.')
            ->defaultNull()
            ->end()
            ->scalarNode('jwks_uri')
            ->info('Where the JWK Set of the client is read back from (RFC 7591 §2); HTTPS, or plain HTTP on a loopback host, no redirect followed. Exclusive with jwks.')
            ->defaultNull()
            ->end()
            ->scalarNode('request_object_signing_alg')
            ->info('The JWS algorithm the request objects of this client are signed with (OIDC Registration §2), among those the provider is wired with; left out, any of them verifies one. The value "none" is the named exception of decision 0006: the objects of that client carry no signature and are read all the same, which no FAPI client registers. A client that names an algorithm publishes its keys in jwks or behind a jwks_uri.')
            ->defaultNull()
            ->end()
            ->arrayNode('request_uris')
            ->info('The URLs a request object of this client is read back from (OIDC Registration §2), compared byte for byte with the request_uri of a request; one that is not registered is refused before any request leaves the process, which is what require_request_uri_registration announces.')
            ->scalarPrototype()
            ->end()
            ->end()
            ->scalarNode(CertificateIdentities::SUBJECT_DN)
            ->info('The subject distinguished name of the certificate this client presents (RFC 8705 §2.1.2), in the string form of RFC 4514; it is written back at boot the way the provider writes the name it reads out of a certificate, so a name as "openssl x509 -noout -subject -nameopt RFC2253" prints it is registered as it is. One of the five keys below, and one only, for a client that authenticates with tls_client_auth.')
            ->defaultNull()
            ->end()
            ->scalarNode(CertificateIdentities::SAN_DNS)
            ->info('The dNSName entry of the subject alternative name extension this client is recognised by (RFC 8705 §2.1.2), compared without regard to case (RFC 4343 §1).')
            ->defaultNull()
            ->end()
            ->scalarNode(CertificateIdentities::SAN_URI)
            ->info('The uniformResourceIdentifier entry this client is recognised by (RFC 8705 §2.1.2), compared as the text it is.')
            ->defaultNull()
            ->end()
            ->scalarNode(CertificateIdentities::SAN_IP)
            ->info('The iPAddress entry this client is recognised by (RFC 8705 §2.1.2), in dotted decimal or colon-delimited hexadecimal; it is compared as the octets it stands for, not as the text.')
            ->defaultNull()
            ->end()
            ->scalarNode(CertificateIdentities::SAN_EMAIL)
            ->info('The rfc822Name entry this client is recognised by (RFC 8705 §2.1.2), compared as it is written (RFC 5321 §2.4).')
            ->defaultNull()
            ->end()
            ->end()
            ->end()
            ->end()
            ->end();
    }

    /**
     * By the name the mappings use (architecture §5.3).
     */
    public const array DBAL_TYPES = [
        IssuerType::NAME => IssuerType::class,
        SubjectType::NAME => SubjectType::class,
        EmailAddressType::NAME => EmailAddressType::class,
        AddressType::NAME => AddressType::class,
        AuthenticationProofsType::NAME => AuthenticationProofsType::class,
        GeoLocationType::NAME => GeoLocationType::class,
        DeviceType::NAME => DeviceType::class,
        RedirectUriType::NAME => RedirectUriType::class,
        ScopesType::NAME => ScopesType::class,
        ClaimsRequestType::NAME => ClaimsRequestType::class,
        CodeChallengeType::NAME => CodeChallengeType::class,
        ConfirmationType::NAME => ConfirmationType::class,
        BytesType::NAME => BytesType::class,
        PasskeyUserHandleType::NAME => PasskeyUserHandleType::class,
        AuthenticationContextPolicyType::NAME => AuthenticationContextPolicyType::class,
        BackupCodesType::NAME => BackupCodesType::class,
    ];

    /**
     * Doctrine gets the mappings, the types and the migrations of the bundle (architecture §5.3); the
     * security component gets the hasher of its users (§5.4); the rate limiter gets the limiter of the
     * attempts at a code (§3.4), a rule of the core the application does not tune. The firewall is the
     * application's to declare.
     */
    public function prependExtension(ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $bundleDir = dirname(__DIR__);
        if ($builder->hasExtension('doctrine')) {
            $builder->prependExtensionConfig('doctrine', [
                'dbal' => [
                    'types' => self::DBAL_TYPES,
                ],
                'orm' => [
                    'mappings' => [
                        'HeidiCore' => [
                            'type' => 'xml',
                            'is_bundle' => false,
                            'dir' => $bundleDir . '/config/doctrine/core',
                            'prefix' => 'Heidi\\Core\\Domain',
                            'alias' => 'HeidiCore',
                        ],
                        'HeidiOidc' => [
                            'type' => 'xml',
                            'is_bundle' => false,
                            'dir' => $bundleDir . '/config/doctrine/oidc',
                            'prefix' => 'Heidi\\Oidc\\Domain',
                            'alias' => 'HeidiOidc',
                        ],
                    ],
                ],
            ]);
        }
        if ($builder->hasExtension('security')) {
            $builder->prependExtensionConfig('security', [
                'password_hashers' => [
                    SecurityUser::class => [
                        'id' => CorePasswordHasher::class,
                    ],
                ],
            ]);
        }
        if ($builder->hasExtension('rate_limiter')) {
            $limiters = [];
            foreach (RateLimitedAttempts::LIMITERS as $limiter) {
                $limiters[$limiter] = [
                    'policy' => 'sliding_window',
                    'limit' => RateLimitedAttempts::LIMIT,
                    'interval' => RateLimitedAttempts::INTERVAL,
                ];
            }
            $builder->prependExtensionConfig('rate_limiter', [
                'limiters' => $limiters,
            ]);
        }
        if ($builder->hasExtension('framework')) {
            // the keys of the clients and the assertions already seen live in pools of their own, so that
            // a deployment can point them at a shared store without touching the rest of its cache
            $builder->prependExtensionConfig('framework', [
                'cache' => [
                    'pools' => [
                        'heidi.client_keys' => [
                            'adapter' => 'cache.app',
                        ],
                        'heidi.client_assertions' => [
                            'adapter' => 'cache.app',
                        ],
                    ],
                ],
            ]);
        }
        if ($builder->hasExtension('doctrine_migrations')) {
            $builder->prependExtensionConfig('doctrine_migrations', [
                'migrations_paths' => [
                    'Heidi\\Bundle\\Migrations' => $bundleDir . '/migrations',
                ],
            ]);
        }
    }

    /**
     * @param array<array-key, mixed> $config
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $container->import('../config/services.php');

        if (! $builder->hasParameter('env(HEIDI_PLANE)')) {
            $builder->setParameter('env(HEIDI_PLANE)', Plane::All->value);
        }

        $tenant = self::section($config, 'tenant');
        $keys = self::section($config, 'keys');
        $webauthn = self::section($config, 'webauthn');
        $tokens = self::section($config, 'tokens');
        $mutualTls = self::section($config, 'mutual_tls');

        $services = $container->services();
        $services->get(TenantFactory::class)
            ->arg('$issuer', self::string($tenant, 'issuer'))
            ->arg('$slug', self::string($tenant, 'slug'))
            ->arg('$name', is_string($tenant['name'] ?? null) ? $tenant['name'] : null)
            ->arg('$authenticationClasses', self::section($tenant, 'authentication_classes'));

        // the DSN is an argument, not a parameter: it may carry key material
        $services->set('heidi.kms', EncrypterInterface::class)
            ->factory([service('key_management.factory'), 'fromString'])
            ->args([self::string($keys, 'kms')]);
        $services->set('heidi.kms.envelopes', EnvelopeEncrypter::class)
            ->args([service('heidi.kms')]);
        $services->get(EnvelopeKeySealer::class)
            ->arg('$envelopes', service('heidi.kms.envelopes'))
            ->arg('$kmsKeyId', self::string($keys, 'key_id'));
        $services->get(EnvelopeSecretSealer::class)
            ->arg('$envelopes', service('heidi.kms.envelopes'))
            ->arg('$kmsKeyId', self::string($keys, 'key_id'));
        $services->get(FileSigningKeyRepository::class)
            ->arg('$directory', self::string($keys, 'storage'));
        $services->get(FileMetadataBlobStore::class)
            ->arg('$directory', self::string($webauthn, 'metadata_storage'));
        $services->get(JwksHandler::class)
            ->arg('$maxAge', self::integer($keys, 'jwks_max_age'));
        $services->get(RouterEndpointLocator::class)
            ->arg('$mutualTlsOrigin', is_string($mutualTls['origin'] ?? null) ? $mutualTls['origin'] : null);
        // derived at runtime, once the environment placeholders are numbers
        $services->get(SigningKeyRotator::class)
            ->arg('$stagingDelay', inline_service(DateInterval::class)
                ->factory(StagingDelay::interval(...))
                ->args([isset($keys['staging_delay']) ? self::integer($keys, 'staging_delay') : null, self::integer($keys, 'jwks_max_age')]));

        $services->get(AuthorizationHandler::class)
            ->arg('$codeLifetime', self::seconds($tokens, 'authorization_code_ttl'));
        $services->get(PushedAuthorizationHandler::class)
            ->arg('$lifetime', self::seconds($tokens, 'request_uri_ttl'));
        $services->get(JwtAccessTokenIssuer::class)
            ->arg('$lifetime', self::seconds($tokens, 'access_token_ttl'));
        $services->get(OpaqueAccessTokenIssuer::class)
            ->arg('$lifetime', self::seconds($tokens, 'access_token_ttl'));
        $services->get(JwtIdTokenIssuer::class)
            ->arg('$lifetime', self::seconds($tokens, 'id_token_ttl'));
        $services->get(TokenIssuer::class)
            ->arg('$refreshTokenLifetime', self::seconds($tokens, 'refresh_token_ttl'));
        $services->get(AuthorizationCodeGrant::class)
            ->arg('$refreshTokenFamilyLifetime', self::seconds($tokens, 'refresh_token_absolute_ttl'));

        $services->get(LogoutTokenSender::class)
            ->arg('$timeout', self::float(self::section($config, 'back_channel_logout'), 'timeout'));

        $clientAuthentication = self::section($config, 'client_authentication');
        $services->get(ClientAssertionValidator::class)
            ->arg('$maximumLifetime', self::seconds($clientAuthentication, 'assertion_max_lifetime'))
            ->arg('$leeway', self::seconds($clientAuthentication, 'assertion_leeway'));
        $services->get(ClientKeySetProvider::class)
            ->arg('$cooldown', self::seconds($clientAuthentication, 'jwks_refetch_cooldown'));
        $services->get(ClientJwksFetcher::class)
            ->arg('$timeout', self::float($clientAuthentication, 'jwks_timeout'))
            ->arg('$maximumSize', self::integer($clientAuthentication, 'jwks_max_size'));
        $services->get(ClientJwksCache::class)
            ->arg('$lifetime', self::integer($clientAuthentication, 'jwks_ttl'));

        $requestObjects = self::section($config, 'request_objects');
        $services->get(RequestObjectValidator::class)
            ->arg('$maximumLifetime', self::seconds($requestObjects, 'max_lifetime'))
            ->arg('$leeway', self::seconds($requestObjects, 'leeway'));
        $services->get(RequestObjectFetcher::class)
            ->arg('$timeout', self::float($requestObjects, 'timeout'))
            ->arg('$maximumSize', self::integer($requestObjects, 'max_size'));

        $services->get(ConfigurationClientRepository::class)
            ->arg('$tenantSlug', self::string($tenant, 'slug'))
            ->arg('$definitions', is_array($config['clients'] ?? null) ? $config['clients'] : []);
    }

    /**
     * @param array<array-key, mixed> $config
     *
     * @return array<array-key, mixed>
     */
    private static function section(array $config, string $key): array
    {
        $section = $config[$key] ?? null;

        return is_array($section) ? $section : [];
    }

    /**
     * @param array<array-key, mixed> $section
     */
    private static function string(array $section, string $key): string
    {
        $value = $section[$key] ?? null;
        if (! is_string($value)) {
            throw new InvalidConfigurationException(sprintf('The "heidi" configuration key "%s" must be a string.', $key));
        }

        return $value;
    }

    /**
     * @param array<array-key, mixed> $section
     *
     * @return int|string a number, or the environment placeholder that stands for it until runtime
     */
    private static function integer(array $section, string $key): int|string
    {
        $value = $section[$key] ?? null;
        if (! is_int($value) && ! is_string($value)) {
            throw new InvalidConfigurationException(sprintf('The "heidi" configuration key "%s" must be a number.', $key));
        }

        return $value;
    }

    /**
     * @param array<array-key, mixed> $section
     *
     * @return float|string a number, or the environment placeholder the container resolves into one
     */
    private static function float(array $section, string $key): float|string
    {
        $value = $section[$key] ?? null;
        if (! is_float($value) && ! is_int($value) && ! is_string($value)) {
            throw new InvalidConfigurationException(sprintf('The "heidi" configuration key "%s" must be a number.', $key));
        }

        return is_int($value) ? (float) $value : $value;
    }

    /**
     * A DateInterval built by the container from a number of seconds.
     *
     * @param array<array-key, mixed> $section
     */
    private static function seconds(array $section, string $key): object
    {
        $value = $section[$key] ?? null;
        if (! is_int($value) && ! is_string($value)) {
            throw new InvalidConfigurationException(sprintf('The "heidi" configuration key "%s" must be a number of seconds.', $key));
        }

        return inline_service(DateInterval::class)
            ->args(['PT' . $value . 'S']);
    }
}
