<?php

declare(strict_types=1);

use Heidi\Bundle\Client\ClientAssertionReplayGuard;
use Heidi\Bundle\Client\ClientJwksCache;
use Heidi\Bundle\Client\ClientJwksFetcher;
use Heidi\Bundle\Client\RequestObjectFetcher;
use Heidi\Bundle\Doctrine\Listener\ClientResolver;
use Heidi\Bundle\Doctrine\Repository\DoctrineAccessTokenRepository;
use Heidi\Bundle\Doctrine\Repository\DoctrineAuthenticationSessionRepository;
use Heidi\Bundle\Doctrine\Repository\DoctrineAuthorizationCodeRepository;
use Heidi\Bundle\Doctrine\Repository\DoctrineConsentRepository;
use Heidi\Bundle\Doctrine\Repository\DoctrineCredentialRepository;
use Heidi\Bundle\Doctrine\Repository\DoctrineInteractionRepository;
use Heidi\Bundle\Doctrine\Repository\DoctrinePushedAuthorizationRequestRepository;
use Heidi\Bundle\Doctrine\Repository\DoctrineRefreshTokenRepository;
use Heidi\Bundle\Doctrine\Repository\DoctrineUserRepository;
use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Doctrine\TenantSynchronizer;
use Heidi\Bundle\Dpop\CachedDpopNonce;
use Heidi\Bundle\Dpop\CachedDpopProofReplayGuard;
use Heidi\Bundle\EndSession\FrontChannelLogoutRenderer;
use Heidi\Bundle\EndSession\LogoutChannels;
use Heidi\Bundle\EndSession\LogoutTokenDeliveryBudget;
use Heidi\Bundle\Http\AccountAccess;
use Heidi\Bundle\Http\AuthorizationResponder;
use Heidi\Bundle\Http\BrowserSession;
use Heidi\Bundle\Http\InteractionLocale;
use Heidi\Bundle\Http\InteractionPages;
use Heidi\Bundle\Http\LogoutTokenSender;
use Heidi\Bundle\Http\PasskeyOptionsStore;
use Heidi\Bundle\Http\PasskeysPage;
use Heidi\Bundle\Http\PendingLoginStore;
use Heidi\Bundle\Http\QrCode;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Bundle\Http\ResponseMode\AuthorizationResponseRenderers;
use Heidi\Bundle\Http\ResponseMode\FormPostResponseRenderer;
use Heidi\Bundle\Http\ResponseMode\QueryResponseRenderer;
use Heidi\Bundle\Http\ResponseMode\SignedFormPostResponseRenderer;
use Heidi\Bundle\Http\ResponseMode\SignedQueryResponseRenderer;
use Heidi\Bundle\Http\Tls\ClientCertificateResolverInterface;
use Heidi\Bundle\Http\Tls\EdgeClientCertificateResolver;
use Heidi\Bundle\Http\Tls\PresentedClientCertificate;
use Heidi\Bundle\Http\TotpProvisioningSealer;
use Heidi\Bundle\Http\TotpProvisioningStore;
use Heidi\Bundle\Http\TwoFactorPage;
use Heidi\Bundle\Key\FileTenantKeyRepository;
use Heidi\Bundle\Key\KmsUnavailableListener;
use Heidi\Bundle\MessageHandler\QueueLogoutTokenHandler;
use Heidi\Bundle\Messenger\EventBusDispatcher;
use Heidi\Bundle\Messenger\LogoutTokenGivenUpListener;
use Heidi\Bundle\Messenger\NotificationRetryPolicy;
use Heidi\Bundle\Plane\Plane;
use Heidi\Bundle\Plane\PlaneRequestListener;
use Heidi\Bundle\Routing\RouterEndpointLocator;
use Heidi\Bundle\Scheduler\HeidiSchedule;
use Heidi\Bundle\Security\CorePasswordHasher;
use Heidi\Bundle\Security\DecoyHashListener;
use Heidi\Bundle\Security\IdentityUserProvider;
use Heidi\Bundle\Security\InteractionLoginHandler;
use Heidi\Bundle\Security\LoginFailureListener;
use Heidi\Bundle\Security\LoginSuccessListener;
use Heidi\Bundle\Security\PasskeyLogin;
use Heidi\Bundle\Security\PasskeyLoginAuthenticator;
use Heidi\Bundle\Security\PassportProofs;
use Heidi\Bundle\Security\PasswordAttemptListener;
use Heidi\Bundle\Security\PasswordLogin;
use Heidi\Bundle\Security\RateLimitedAttempts;
use Heidi\Bundle\Security\RefusalCost;
use Heidi\Bundle\Security\SecondFactorGate;
use Heidi\Bundle\Security\TotpLogin;
use Heidi\Bundle\Security\TotpLoginAuthenticator;
use Heidi\Bundle\Security\UserChecker;
use Heidi\Bundle\Tenant\TenantFactory;
use Heidi\Bundle\Webauthn\FileMetadataBlobStore;
use Heidi\Core\Application\Authentication\DecoyHash;
use Heidi\Core\Application\Authentication\LoginCompletion;
use Heidi\Core\Application\Authentication\PasswordAuthenticator;
use Heidi\Core\Application\Authentication\SecondFactorRequirement;
use Heidi\Core\Application\Authentication\SessionOpener;
use Heidi\Core\Application\Authentication\SessionTerminator;
use Heidi\Core\Application\Credential\CredentialRevocation;
use Heidi\Core\Application\Identity\UserProvisioner;
use Heidi\Core\Application\Key\TenantKeyRotator;
use Heidi\Core\Application\Passkey\PasskeyAuthentication;
use Heidi\Core\Application\Passkey\PasskeyEnrolment;
use Heidi\Core\Application\Totp\ActiveTotp;
use Heidi\Core\Application\Totp\TotpAuthentication;
use Heidi\Core\Application\Totp\TotpCodeMatcher;
use Heidi\Core\Application\Totp\TotpEnrolment;
use Heidi\Core\Bridge\JwtLibrary\Algorithm\A256Gcm;
use Heidi\Core\Bridge\JwtLibrary\Algorithm\EcdhEsA256Kw;
use Heidi\Core\Bridge\JwtLibrary\Algorithm\EdDsa;
use Heidi\Core\Bridge\JwtLibrary\Algorithm\Es256;
use Heidi\Core\Bridge\JwtLibrary\Algorithm\Ps256;
use Heidi\Core\Bridge\JwtLibrary\Algorithm\Rs256;
use Heidi\Core\Bridge\JwtLibrary\Algorithm\RsaKeyBits;
use Heidi\Core\Bridge\JwtLibrary\Algorithm\RsaOaep256;
use Heidi\Core\Bridge\JwtLibrary\JoseContentEncryptionAlgorithms;
use Heidi\Core\Bridge\JwtLibrary\JoseEncryptionAlgorithms;
use Heidi\Core\Bridge\JwtLibrary\JoseKeyAlgorithms;
use Heidi\Core\Bridge\JwtLibrary\JoseKeyEncryptionAlgorithms;
use Heidi\Core\Bridge\JwtLibrary\JoseSignatureAlgorithms;
use Heidi\Core\Bridge\JwtLibrary\JwtLibraryJweDecrypter;
use Heidi\Core\Bridge\JwtLibrary\JwtLibraryJwsSigner;
use Heidi\Core\Bridge\JwtLibrary\JwtLibraryJwsVerifier;
use Heidi\Core\Bridge\JwtLibrary\JwtLibraryKeyPairGenerator;
use Heidi\Core\Bridge\Key\SealedKeyProvider;
use Heidi\Core\Bridge\KeyManagement\EnvelopeKeySealer;
use Heidi\Core\Bridge\KeyManagement\EnvelopeSecretSealer;
use Heidi\Core\Bridge\Null\NullGeoLocator;
use Heidi\Core\Bridge\Null\NullUserAgentParser;
use Heidi\Core\Bridge\Otphp\OtphpTotpAlgorithm;
use Heidi\Core\Bridge\Password\NativePasswordHasher;
use Heidi\Core\Bridge\Password\PasswordHasherRegistry;
use Heidi\Core\Bridge\Webauthn\MetadataBlobVerifier;
use Heidi\Core\Bridge\Webauthn\StoredMetadata;
use Heidi\Core\Bridge\Webauthn\WebauthnCeremonies;
use Heidi\Core\Bridge\Webauthn\WebauthnPasskeyAuthenticator;
use Heidi\Core\Bridge\Webauthn\WebauthnPasskeyRegistrar;
use Heidi\Core\Port\AuthenticationSessionRepositoryInterface;
use Heidi\Core\Port\CodeAttemptLimiterInterface;
use Heidi\Core\Port\ContentEncryptionAlgorithmsInterface;
use Heidi\Core\Port\CredentialRepositoryInterface;
use Heidi\Core\Port\DecryptionKeyProviderInterface;
use Heidi\Core\Port\GeoLocatorInterface;
use Heidi\Core\Port\JweDecrypterInterface;
use Heidi\Core\Port\JwsSignerInterface;
use Heidi\Core\Port\JwsVerifierInterface;
use Heidi\Core\Port\KeyAlgorithmsInterface;
use Heidi\Core\Port\KeyEncryptionAlgorithmsInterface;
use Heidi\Core\Port\KeyPairGeneratorInterface;
use Heidi\Core\Port\KeySealerInterface;
use Heidi\Core\Port\MetadataBlobStoreInterface;
use Heidi\Core\Port\PasskeyAuthenticatorInterface;
use Heidi\Core\Port\PasskeyRegistrarInterface;
use Heidi\Core\Port\PasswordAttemptLimiterInterface;
use Heidi\Core\Port\PasswordHasherInterface;
use Heidi\Core\Port\PublicKeySetProviderInterface;
use Heidi\Core\Port\SecretSealerInterface;
use Heidi\Core\Port\SignatureAlgorithmsInterface;
use Heidi\Core\Port\SigningKeyProviderInterface;
use Heidi\Core\Port\TenantKeyRepositoryInterface;
use Heidi\Core\Port\TotpAlgorithmInterface;
use Heidi\Core\Port\UserAgentParserInterface;
use Heidi\Core\Port\UserRepositoryInterface;
use Heidi\Oidc\Application\Authorization\AuthorizationHandler;
use Heidi\Oidc\Application\Authorization\AuthorizationRequestParser;
use Heidi\Oidc\Application\Authorization\IdTokenHintVerifier;
use Heidi\Oidc\Application\Authorization\RequestObjectReader;
use Heidi\Oidc\Application\Authorization\RequestObjectResolver;
use Heidi\Oidc\Application\Authorization\RequestObjectValidator;
use Heidi\Oidc\Application\Authorization\ResponseDocumentIssuer;
use Heidi\Oidc\Application\Claims\PublicSubjectIdentifierResolver;
use Heidi\Oidc\Application\Claims\StandardClaimsProvider;
use Heidi\Oidc\Application\Client\ClientAssertionValidator;
use Heidi\Oidc\Application\Client\ClientAuthenticationMethods;
use Heidi\Oidc\Application\Client\ClientAuthenticator;
use Heidi\Oidc\Application\Client\ClientDocumentIssuer;
use Heidi\Oidc\Application\Client\ClientKeySetProvider;
use Heidi\Oidc\Application\Client\Method\ClientSecretBasic;
use Heidi\Oidc\Application\Client\Method\ClientSecretJwt;
use Heidi\Oidc\Application\Client\Method\ClientSecretPost;
use Heidi\Oidc\Application\Client\Method\NoAuthentication;
use Heidi\Oidc\Application\Client\Method\PrivateKeyJwt;
use Heidi\Oidc\Application\Client\Method\SelfSignedTlsClientAuth;
use Heidi\Oidc\Application\Client\Method\TlsClientAuth;
use Heidi\Oidc\Application\Discovery\DiscoveryHandler;
use Heidi\Oidc\Application\Discovery\JwksHandler;
use Heidi\Oidc\Application\Dpop\DpopProofValidator;
use Heidi\Oidc\Application\Dpop\DpopProofVerifier;
use Heidi\Oidc\Application\EndSession\BackChannelLogout;
use Heidi\Oidc\Application\EndSession\EndSessionHandler;
use Heidi\Oidc\Application\EndSession\EndSessionRequestParser;
use Heidi\Oidc\Application\EndSession\FrontChannelLogout;
use Heidi\Oidc\Application\EndSession\LogoutTokenIssuer;
use Heidi\Oidc\Application\Introspection\IntrospectionHandler;
use Heidi\Oidc\Application\Key\AccessTokenJwsKind;
use Heidi\Oidc\Application\Key\IdTokenJwsKind;
use Heidi\Oidc\Application\Key\LogoutTokenJwsKind;
use Heidi\Oidc\Application\Key\PushedRequestJweKind;
use Heidi\Oidc\Application\Key\RequestObjectJweKind;
use Heidi\Oidc\Application\Key\ResponseDocumentJwsKind;
use Heidi\Oidc\Application\PushedAuthorization\PushedAuthorizationHandler;
use Heidi\Oidc\Application\PushedAuthorization\PushedAuthorizationRequestResolver;
use Heidi\Oidc\Application\Revocation\RevocationHandler;
use Heidi\Oidc\Application\Token\AccessTokenInspector;
use Heidi\Oidc\Application\Token\AccessTokenIssuer;
use Heidi\Oidc\Application\Token\AccessTokenVerifier;
use Heidi\Oidc\Application\Token\AuthorizationCodeGrant;
use Heidi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Heidi\Oidc\Application\Token\JwtIdTokenIssuer;
use Heidi\Oidc\Application\Token\OpaqueAccessTokenIssuer;
use Heidi\Oidc\Application\Token\RefreshTokenGrant;
use Heidi\Oidc\Application\Token\RefreshTokenRevocation;
use Heidi\Oidc\Application\Token\TokenHandler;
use Heidi\Oidc\Application\Token\TokenIssuer;
use Heidi\Oidc\Application\UserInfo\UserInfoHandler;
use Heidi\Oidc\Bridge\Configuration\ConfigurationClientRepository;
use Heidi\Oidc\Bridge\JwtLibrary\JwtLibraryClientAssertionSecretVerifier;
use Heidi\Oidc\Bridge\JwtLibrary\JwtLibraryCompactJwtReader;
use Heidi\Oidc\Bridge\JwtLibrary\JwtLibraryJweEncrypter;
use Heidi\Oidc\Bridge\JwtLibrary\JwtLibraryJwtKeyVerifier;
use Heidi\Oidc\Bridge\JwtLibrary\JwtLibraryProofKeyVerifier;
use Heidi\Oidc\Bridge\Null\NoDpopNonce;
use Heidi\Oidc\Bridge\Pki\PkiFrameworkCertificateReader;
use Heidi\Oidc\Domain\Client\AccessTokenFormat;
use Heidi\Oidc\Port\AccessTokenIssuerInterface;
use Heidi\Oidc\Port\AccessTokenRepositoryInterface;
use Heidi\Oidc\Port\AuthorizationCodeRepositoryInterface;
use Heidi\Oidc\Port\CertificateReaderInterface;
use Heidi\Oidc\Port\ClaimsProviderInterface;
use Heidi\Oidc\Port\ClientAssertionReplayGuardInterface;
use Heidi\Oidc\Port\ClientAssertionSecretVerifierInterface;
use Heidi\Oidc\Port\ClientAuthenticationMethodsInterface;
use Heidi\Oidc\Port\ClientJwksCacheInterface;
use Heidi\Oidc\Port\ClientJwksFetcherInterface;
use Heidi\Oidc\Port\ClientRepositoryInterface;
use Heidi\Oidc\Port\CompactJwtReaderInterface;
use Heidi\Oidc\Port\ConsentRepositoryInterface;
use Heidi\Oidc\Port\DpopProofReplayGuardInterface;
use Heidi\Oidc\Port\EndpointLocatorInterface;
use Heidi\Oidc\Port\IdTokenIssuerInterface;
use Heidi\Oidc\Port\InteractionRepositoryInterface;
use Heidi\Oidc\Port\JweEncrypterInterface;
use Heidi\Oidc\Port\JwtKeyVerifierInterface;
use Heidi\Oidc\Port\LoggedInClientsInterface;
use Heidi\Oidc\Port\MutualTlsEndpointLocatorInterface;
use Heidi\Oidc\Port\ProofKeyVerifierInterface;
use Heidi\Oidc\Port\ProvableMethodsInterface;
use Heidi\Oidc\Port\PushedAuthorizationRequestRepositoryInterface;
use Heidi\Oidc\Port\PushedAuthorizationRequirementInterface;
use Heidi\Oidc\Port\RefreshTokenRepositoryInterface;
use Heidi\Oidc\Port\RequestObjectFetcherInterface;
use Heidi\Oidc\Port\LogoutTokenDeliveryInterface;
use Heidi\Oidc\Port\ServedLogoutChannelsInterface;
use Heidi\Oidc\Port\ServedResponseModesInterface;
use Heidi\Oidc\Port\SubjectIdentifierResolverInterface;
use Heidi\Oidc\Port\UnsignedRequestObjectsInterface;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\HS256;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\inline_service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\tagged_iterator;
use Webauthn\MetadataService\CertificateChain\CertificateChainValidator;
use Webauthn\MetadataService\CertificateChain\PhpCertificateChainValidator;
use Webauthn\MetadataService\MetadataStatementRepository;
use Webauthn\MetadataService\StatusReportRepository;

/*
 * Every service of the core, of the module and of the bundle, autowired, the ports aliased to their one
 * implementation (architecture §3.4, §4.11, §5.2 to §5.4).
 */
return static function (ContainerConfigurator $container): void {
    $services = $container->services();
    $services
        ->defaults()
        ->autowire()
        ->autoconfigure()
        ->private()
        // the core announces in PSR-14; what listens is the event bus, never the dispatcher of the kernel
        ->bind(EventDispatcherInterface::class, service(EventBusDispatcher::class));

    // The bundle
    $services->set(EventBusDispatcher::class)->args([service('event.bus')]);
    $services->set(PlaneRequestListener::class)->args(['%env(enum:' . Plane::class . ':HEIDI_PLANE)%']);
    $services->set(TenantFactory::class);

    // The bundle: the two planes (architecture §5.2)
    $services->load('Heidi\\Bundle\\Controller\\', '../src/Controller/');
    $services->set(RequestContextFactory::class);
    $services->set(BrowserSession::class);
    $services->set(InteractionPages::class);
    // what every page of the account asks first: the session of this browser, and the form token when it posts
    $services->set(AccountAccess::class);
    $services->set(InteractionLocale::class)->args([
        '$enabledLocales' => '%kernel.enabled_locales%',
        '$defaultLocale' => '%kernel.default_locale%',
    ]);
    // how the answer of the authorization endpoint reaches the client (Multiple Response Type Encoding
    // Practices §2.1): one class per mode, and what is tagged is what the parser accepts and what the
    // discovery document announces, never an enumeration kept beside them
    $services->set(QueryResponseRenderer::class)->tag('heidi.response_mode');
    $services->set(FormPostResponseRenderer::class)->tag('heidi.response_mode');
    // JARM §2.1: the same two deliveries, of a document the tenant signs rather than of the parameters
    $services->set(SignedQueryResponseRenderer::class)->tag('heidi.response_mode');
    $services->set(SignedFormPostResponseRenderer::class)->tag('heidi.response_mode');
    $services->set(AuthorizationResponseRenderers::class)->args([tagged_iterator('heidi.response_mode')]);
    $services->alias(ServedResponseModesInterface::class, AuthorizationResponseRenderers::class);
    $services->set(AuthorizationResponder::class);
    $services->set(PasskeyOptionsStore::class);
    $services->set(PasskeysPage::class);
    // the second factor: the login held between the password and the code, the provisioning of an enrolment sealed under the KMS of the tenant, the QR code drawn by the bundle
    $services->set(PendingLoginStore::class);
    $services->set(TotpProvisioningSealer::class);
    $services->set(TotpProvisioningStore::class);
    $services->set(QrCode::class);
    $services->set(TwoFactorPage::class);
    $services->set(RouterEndpointLocator::class);
    $services->alias(EndpointLocatorInterface::class, RouterEndpointLocator::class);
    $services->alias(MutualTlsEndpointLocatorInterface::class, RouterEndpointLocator::class);
    // the certificate a client presented at the handshake, read from what the edge proves and never from
    // a header (decision 0006, docs/mtls-at-the-edge.md); a deployment behind another proxy replaces this
    // implementation rather than teaching it a header to trust
    $services->set(EdgeClientCertificateResolver::class);
    $services->alias(ClientCertificateResolverInterface::class, EdgeClientCertificateResolver::class);
    $services->set(PresentedClientCertificate::class);

    // The bundle: the console (architecture §5.5)
    $services->load('Heidi\\Bundle\\Command\\', '../src/Command/');

    // The bundle: the endpoints of the FIDO2 server API for the FIDO Conformance Tools (architecture §7); their
    // routes are a file of their own (config/routes/fido-conformance.php) an application imports in development
    // only, and a controller no route names is dropped from the container
    $services->load('Heidi\\Bundle\\Fido\\Conformance\\', '../src/Fido/Conformance/');

    // The bundle: the handlers of its own messages and what time does on its own (architecture §5.6)
    $services->load('Heidi\\Bundle\\MessageHandler\\', '../src/MessageHandler/');
    $services->get(QueueLogoutTokenHandler::class)->tag('heidi.logout_channel');
    $services->set(HeidiSchedule::class);
    // what carries a logout token to a client, and what says the provider gave up on one (§4.9)
    $services->set(LogoutTokenSender::class);
    $services->set(LogoutTokenGivenUpListener::class);
    // how long a notification the provider carries to a third party is tried again: the policy the
    // application gives to the transport of that lane, and the one thing that says so
    $services->set(NotificationRetryPolicy::class);

    // The bundle: security (architecture §5.4); the application names these in its firewall
    $services->set(IdentityUserProvider::class);
    $services->set(CorePasswordHasher::class);
    $services->set(UserChecker::class);
    $services->set(InteractionLoginHandler::class);
    $services->set(LoginSuccessListener::class);
    $services->set(LoginFailureListener::class);
    $services->set(PasskeyLoginAuthenticator::class);
    // a password of a user who holds a second factor is held until the code, verified by the second authenticator of the firewall
    $services->set(SecondFactorGate::class);
    $services->set(TotpLoginAuthenticator::class);
    // what the logins of the firewall prove, read by the listener and announced by the discovery (decision 0010):
    // one class per login, and what is tagged is what the provider announces
    $services->set(PasswordLogin::class)->tag('heidi.login');
    $services->set(PasskeyLogin::class)->tag('heidi.login');
    $services->set(TotpLogin::class)->tag('heidi.login');
    $services->set(PassportProofs::class)->args([tagged_iterator('heidi.login')]);
    $services->alias(ProvableMethodsInterface::class, PassportProofs::class);
    // the attempts at a code and at a password, counted per user by the two limiters the bundle declares in the framework (architecture §3.4)
    $services->set('heidi.security.code_attempts', RateLimitedAttempts::class)->args([service('limiter.' . RateLimitedAttempts::CODE_LIMITER)]);
    $services->alias(CodeAttemptLimiterInterface::class, 'heidi.security.code_attempts');
    $services->set('heidi.security.password_attempts', RateLimitedAttempts::class)->args([service('limiter.' . RateLimitedAttempts::PASSWORD_LIMITER)]);
    $services->alias(PasswordAttemptLimiterInterface::class, 'heidi.security.password_attempts');
    $services->set(PasswordAttemptListener::class);
    // the decoy hash of the core paid where the firewall refuses a password before any hash (architecture §5.4)
    $services->set(RefusalCost::class);
    $services->set(DecoyHashListener::class);
    // a KMS that does not answer or refuses is a 503 wherever it stands on the path of a request (architecture §3.3)
    $services->set(KmsUnavailableListener::class);

    // The bundle: persistence (architecture §5.3); no service holds a Tenant, an entity is not a service
    $services->set(TenantProvider::class)->tag('kernel.reset', [
        'method' => 'reset',
    ])->tag('doctrine.event_listener', [
        'event' => 'onClear',
    ]);
    $services->set(TenantSynchronizer::class);
    $services->set(ClientResolver::class)->tag('doctrine.orm.entity_listener');
    $services->set(DoctrineUserRepository::class);
    $services->alias(UserRepositoryInterface::class, DoctrineUserRepository::class);
    $services->set(DoctrineCredentialRepository::class);
    $services->alias(CredentialRepositoryInterface::class, DoctrineCredentialRepository::class);
    $services->set(DoctrineAuthenticationSessionRepository::class);
    $services->alias(AuthenticationSessionRepositoryInterface::class, DoctrineAuthenticationSessionRepository::class);
    $services->set(DoctrineInteractionRepository::class);
    $services->alias(InteractionRepositoryInterface::class, DoctrineInteractionRepository::class);
    $services->set(DoctrineAuthorizationCodeRepository::class);
    $services->alias(AuthorizationCodeRepositoryInterface::class, DoctrineAuthorizationCodeRepository::class);
    // the grants of a session name the clients to tell it ended (Back-Channel Logout 1.0 §2.6)
    $services->alias(LoggedInClientsInterface::class, DoctrineAuthorizationCodeRepository::class);
    $services->set(DoctrinePushedAuthorizationRequestRepository::class);
    $services->alias(PushedAuthorizationRequestRepositoryInterface::class, DoctrinePushedAuthorizationRequestRepository::class);
    $services->set(DoctrineRefreshTokenRepository::class);
    $services->alias(RefreshTokenRepositoryInterface::class, DoctrineRefreshTokenRepository::class);
    $services->set(DoctrineAccessTokenRepository::class);
    $services->alias(AccessTokenRepositoryInterface::class, DoctrineAccessTokenRepository::class);
    $services->set(DoctrineConsentRepository::class);
    $services->alias(ConsentRepositoryInterface::class, DoctrineConsentRepository::class);

    // The core: keys
    $services->set(EnvelopeKeySealer::class);
    $services->alias(KeySealerInterface::class, EnvelopeKeySealer::class);
    $services->set(EnvelopeSecretSealer::class);
    $services->alias(SecretSealerInterface::class, EnvelopeSecretSealer::class);
    $services->set(FileTenantKeyRepository::class);
    $services->alias(TenantKeyRepositoryInterface::class, FileTenantKeyRepository::class);
    $services->set(SealedKeyProvider::class);
    $services->alias(SigningKeyProviderInterface::class, SealedKeyProvider::class);
    $services->alias(DecryptionKeyProviderInterface::class, SealedKeyProvider::class);
    $services->alias(PublicKeySetProviderInterface::class, SealedKeyProvider::class);
    // The algorithms the provider signs with: one class per algorithm, tagged; the first tagged one is
    // the default, the one an access token, a signed introspection response and a client that registered
    // none are signed with. A new algorithm is a class and a line here, and the discovery document, the
    // key commands and the signer follow on their own. RS256 is mandatory (OIDC Core §15.1) and FAPI 2.0
    // §5.2.2 refuses it: a deployment that follows that profile drops this line and keeps the others.
    $services->set(RsaKeyBits::class);
    $services
        ->set(Rs256::class)
        ->args([service(RsaKeyBits::class)])
        ->tag('heidi.signature_algorithm');
    $services
        ->set(Ps256::class)
        ->args([service(RsaKeyBits::class)])
        ->tag('heidi.signature_algorithm');
    $services->set(Es256::class)->tag('heidi.signature_algorithm');
    $services->set(EdDsa::class)->tag('heidi.signature_algorithm');
    $services->set(JoseSignatureAlgorithms::class)->args([tagged_iterator('heidi.signature_algorithm')]);
    $services->alias(SignatureAlgorithmsInterface::class, JoseSignatureAlgorithms::class);
    // The algorithms a client encrypts to the provider with, wired the same way: the "alg" that wraps or
    // agrees on the content encryption key, and the "enc" that encrypts the payload. RFC 8725 §3.4 keeps
    // RSA1_5 out, and a deployment nobody encrypts to drops these lines: it then generates no encryption
    // key, publishes none and announces none, the document and the decrypter reading this one list.
    $services->set(EcdhEsA256Kw::class)->tag('heidi.key_encryption_algorithm');
    $services
        ->set(RsaOaep256::class)
        ->args([service(RsaKeyBits::class)])
        ->tag('heidi.key_encryption_algorithm');
    $services->set(A256Gcm::class)->tag('heidi.content_encryption_algorithm');
    $services->set(JoseKeyEncryptionAlgorithms::class)->args([tagged_iterator('heidi.key_encryption_algorithm')]);
    $services->alias(KeyEncryptionAlgorithmsInterface::class, JoseKeyEncryptionAlgorithms::class);
    $services->set(JoseContentEncryptionAlgorithms::class)->args([tagged_iterator('heidi.content_encryption_algorithm')]);
    $services->alias(ContentEncryptionAlgorithmsInterface::class, JoseContentEncryptionAlgorithms::class);
    $services->set(JoseEncryptionAlgorithms::class);
    // What a key may be generated for, the two lists read as one: the key commands and the key files
    // resolve an algorithm name against this, whatever the key is published for
    $services->set(JoseKeyAlgorithms::class);
    $services->alias(KeyAlgorithmsInterface::class, JoseKeyAlgorithms::class);
    $services->set(JwtLibraryKeyPairGenerator::class);
    $services->alias(KeyPairGeneratorInterface::class, JwtLibraryKeyPairGenerator::class);
    $services->set(JwtLibraryJwsSigner::class);
    $services->alias(JwsSignerInterface::class, JwtLibraryJwsSigner::class);
    $services->set(JwtLibraryJwsVerifier::class);
    $services->alias(JwsVerifierInterface::class, JwtLibraryJwsVerifier::class);
    $services->set(JwtLibraryJweDecrypter::class);
    $services->alias(JweDecrypterInterface::class, JwtLibraryJweDecrypter::class);
    // the modules tag the kinds of artifact bound to a key, each naming the use it holds back; the
    // rotation dates a retirement from the longest of those of the use of the key retiring (architecture §3.3)
    $services->set(TenantKeyRotator::class)->args([
        '$artifacts' => tagged_iterator('heidi.key_bound_artifact'),
    ]);

    // The core: passwords; the hashers of one algorithm (AlgorithmPasswordHasherInterface) are tagged by hand, the registry is the port the use cases see
    $services->set(NativePasswordHasher::class)->tag('heidi.password_hasher');
    $services->set(PasswordHasherRegistry::class)->args([tagged_iterator('heidi.password_hasher')]);
    $services->alias(PasswordHasherInterface::class, PasswordHasherRegistry::class);
    // the hash a refused password is verified against when none of the user could be, computed once per process
    $services->set(DecoyHash::class);

    // The core: the WebAuthn ceremonies on webauthn-lib (architecture §3.4), on the FIDO metadata of the store
    // the console fills (the two commands), read once per process; the chains of a blob and of an attestation
    // are checked by the validator of the library, which fetches a CRL when the certificate names one and
    // lets an unreachable one pass, as the library does
    $services->set(FileMetadataBlobStore::class);
    $services->alias(MetadataBlobStoreInterface::class, FileMetadataBlobStore::class);
    $services->set(StoredMetadata::class);
    $services->alias(MetadataStatementRepository::class, StoredMetadata::class);
    $services->alias(StatusReportRepository::class, StoredMetadata::class);
    $services->set(PhpCertificateChainValidator::class);
    $services->alias(CertificateChainValidator::class, PhpCertificateChainValidator::class);
    $services->set(MetadataBlobVerifier::class);
    $services->set(WebauthnCeremonies::class);
    $services->set(WebauthnPasskeyRegistrar::class);
    $services->alias(PasskeyRegistrarInterface::class, WebauthnPasskeyRegistrar::class);
    $services->set(WebauthnPasskeyAuthenticator::class);
    $services->alias(PasskeyAuthenticatorInterface::class, WebauthnPasskeyAuthenticator::class);

    // The core: RFC 6238 on otphp (architecture §3.4)
    $services->set(OtphpTotpAlgorithm::class);
    $services->alias(TotpAlgorithmInterface::class, OtphpTotpAlgorithm::class);
    $services->set(TotpCodeMatcher::class);
    $services->set(ActiveTotp::class);

    // The core: request context enrichment (architecture §3.5)
    $services->set(NullGeoLocator::class);
    $services->alias(GeoLocatorInterface::class, NullGeoLocator::class);
    $services->set(NullUserAgentParser::class);
    $services->alias(UserAgentParserInterface::class, NullUserAgentParser::class);

    // The core: use cases
    $services->set(PasswordAuthenticator::class);
    $services->set(LoginCompletion::class);
    $services->set(SecondFactorRequirement::class);
    $services->set(PasskeyEnrolment::class);
    $services->set(PasskeyAuthentication::class);
    $services->set(TotpEnrolment::class);
    $services->set(TotpAuthentication::class);
    $services->set(CredentialRevocation::class);
    $services->set(SessionOpener::class);
    $services->set(SessionTerminator::class);
    $services->set(UserProvisioner::class);

    // The module: clients
    $services->set(ConfigurationClientRepository::class);
    $services->alias(ClientRepositoryInterface::class, ConfigurationClientRepository::class);
    // RFC 9126 §5: whether the document says a request must be pushed is what the registered clients
    // require, read where they are declared and nowhere else (issue #98)
    $services->alias(PushedAuthorizationRequirementInterface::class, ConfigurationClientRepository::class);
    $services->alias(UnsignedRequestObjectsInterface::class, ConfigurationClientRepository::class);
    // how a client authenticates at the endpoints that authenticate one (RFC 6749 §2.3, OIDC Core §9):
    // one class per method, tagged, and what is tagged is what a client may register, what the endpoints
    // take and what the discovery document announces, never an enumeration kept beside them (issue #98).
    // The first tagged one is what a client that names none registers. FAPI 2.0 §5.2.2 takes
    // private_key_jwt and mTLS alone: a deployment that follows the profile drops the three lines that
    // prove a shared secret, and the provider stops taking them and stops announcing them.
    $services->set(ClientSecretBasic::class)->tag('heidi.client_authentication_method');
    $services->set(ClientSecretPost::class)->tag('heidi.client_authentication_method');
    $services->set(PrivateKeyJwt::class)->tag('heidi.client_authentication_method');
    $services->set(ClientSecretJwt::class)->tag('heidi.client_authentication_method');
    $services->set(TlsClientAuth::class)->tag('heidi.client_authentication_method');
    $services->set(SelfSignedTlsClientAuth::class)->tag('heidi.client_authentication_method');
    $services->set(NoAuthentication::class)->tag('heidi.client_authentication_method');
    $services->set(ClientAuthenticationMethods::class)->args([tagged_iterator('heidi.client_authentication_method')]);
    $services->alias(ClientAuthenticationMethodsInterface::class, ClientAuthenticationMethods::class);
    $services->set(ClientAuthenticator::class);
    // what reads an X.509 certificate and writes a distinguished name back (RFC 8705 §2.1.2): the same
    // reader on both sides, so that a name registered for a client and a name read out of a certificate
    // are written the same way and compare predictably
    $services->set(PkiFrameworkCertificateReader::class);
    $services->alias(CertificateReaderInterface::class, PkiFrameworkCertificateReader::class);
    // what reads a client assertion and what verifies it (RFC 7523 §2.2): against the keys the client
    // publishes, with the algorithms the provider is wired with, or against the secret it registered,
    // with HS256 and nothing else (RFC 8725 §3.1)
    $services->set(JwtLibraryCompactJwtReader::class);
    $services->alias(CompactJwtReaderInterface::class, JwtLibraryCompactJwtReader::class);
    $services->set('heidi.oidc.client_assertion.signature_algorithms', AlgorithmManager::class)->factory([service(JoseSignatureAlgorithms::class), 'manager']);
    $services->set(JwtLibraryJwtKeyVerifier::class)->args([service('heidi.oidc.client_assertion.signature_algorithms')]);
    $services->alias(JwtKeyVerifierInterface::class, JwtLibraryJwtKeyVerifier::class);
    // What the provider encrypts for a client: the key management and content encryption algorithms it is
    // wired with, the same ones it opens a JWE with, read from the two registries of the core and never
    // from a list kept beside them
    $services->set('heidi.oidc.client_encryption.algorithms', AlgorithmManager::class)->factory([service(JoseEncryptionAlgorithms::class), 'manager']);
    $services->set(JwtLibraryJweEncrypter::class)->args([service('heidi.oidc.client_encryption.algorithms')]);
    $services->alias(JweEncrypterInterface::class, JwtLibraryJweEncrypter::class);
    $services->set(ClientDocumentIssuer::class);
    $services->set('heidi.oidc.client_assertion.mac_algorithms', AlgorithmManager::class)->args([[inline_service(HS256::class)]]);
    $services->set(JwtLibraryClientAssertionSecretVerifier::class)->args([service('heidi.oidc.client_assertion.mac_algorithms')]);
    $services->alias(ClientAssertionSecretVerifierInterface::class, JwtLibraryClientAssertionSecretVerifier::class);
    $services->set(ClientAssertionValidator::class);
    $services->set(ClientKeySetProvider::class);
    // the keys of a client read back over HTTPS, kept in a pool the workers share, and the "jti" of the
    // assertions already seen kept until they expire
    $services->set(ClientJwksFetcher::class);
    $services->alias(ClientJwksFetcherInterface::class, ClientJwksFetcher::class);
    $services->set(ClientJwksCache::class)->args([
        '$cache' => service('heidi.client_keys'),
    ]);
    $services->alias(ClientJwksCacheInterface::class, ClientJwksCache::class);
    $services->set(ClientAssertionReplayGuard::class)->args([
        '$cache' => service('heidi.client_assertions'),
    ]);
    $services->alias(ClientAssertionReplayGuardInterface::class, ClientAssertionReplayGuard::class);

    // The module: the proof of possession a request carries (RFC 9449), read with the reader every JWT
    // a client signs is read with and verified against the key of its own header, with the algorithms
    // the provider is wired with; the proofs already seen and the nonces it hands out live in a pool
    // the workers share, as the assertions already seen do
    $services->set(JwtLibraryProofKeyVerifier::class)->args([service('heidi.oidc.client_assertion.signature_algorithms')]);
    $services->alias(ProofKeyVerifierInterface::class, JwtLibraryProofKeyVerifier::class);
    $services->set(CachedDpopProofReplayGuard::class)->args([
        '$cache' => service('heidi.dpop'),
    ]);
    $services->alias(DpopProofReplayGuardInterface::class, CachedDpopProofReplayGuard::class);
    $services->set(NoDpopNonce::class);
    $services->set(CachedDpopNonce::class)->args([
        '$cache' => service('heidi.dpop'),
    ]);
    $services->set(DpopProofValidator::class);
    $services->set(DpopProofVerifier::class);

    // The module: subject and claims
    $services->set(PublicSubjectIdentifierResolver::class);
    $services->alias(SubjectIdentifierResolverInterface::class, PublicSubjectIdentifierResolver::class);
    $services->set(StandardClaimsProvider::class);
    $services->alias(ClaimsProviderInterface::class, StandardClaimsProvider::class);

    // The module: authorization endpoint, the pushed request the browser may come back with, and the
    // request object a client signs (RFC 9101), read with the very reader and verifier a client
    // assertion is read with, against the keys the client publishes
    $services->set(AuthorizationRequestParser::class);
    $services->set(PushedAuthorizationRequestResolver::class);
    $services->set(RequestObjectValidator::class);
    // What arrived: the object in clear, or the object inside the JWE a client encrypted to a key of the
    // tenant (RFC 9101 §6.1)
    $services->set(RequestObjectReader::class);
    $services->set(RequestObjectResolver::class);
    $services->set(RequestObjectFetcher::class);
    $services->alias(RequestObjectFetcherInterface::class, RequestObjectFetcher::class);
    $services->set(PushedAuthorizationHandler::class);
    // What a client may still be encrypting to a key of the tenant, which is what holds an encryption key
    // back from retiring: each one reads its lifetime where that lifetime is set (architecture §3.3)
    $services->set(RequestObjectJweKind::class)->tag('heidi.key_bound_artifact');
    $services->set(PushedRequestJweKind::class)->tag('heidi.key_bound_artifact');
    $services->set(IdTokenHintVerifier::class);
    $services->set(AuthorizationHandler::class);
    // JARM §2.1: what the two signed modes deliver, minted where every other JWS of the tenant is
    $services->set(ResponseDocumentIssuer::class);

    // The module: token endpoint; the grants are tagged by hand, the issuers named by the format each one writes
    $services->set(JwtAccessTokenIssuer::class);
    $services->set(OpaqueAccessTokenIssuer::class);
    $services->set(AccessTokenIssuer::class)->args([
        '$issuers' => [
            AccessTokenFormat::Jwt->value => service(JwtAccessTokenIssuer::class),
            AccessTokenFormat::Opaque->value => service(OpaqueAccessTokenIssuer::class),
        ],
    ]);
    $services->alias(AccessTokenIssuerInterface::class, AccessTokenIssuer::class);
    $services->set(JwtIdTokenIssuer::class);
    $services->alias(IdTokenIssuerInterface::class, JwtIdTokenIssuer::class);
    $services->set(IdTokenJwsKind::class)->tag('heidi.key_bound_artifact');
    $services->set(AccessTokenJwsKind::class)->tag('heidi.key_bound_artifact');
    $services->set(ResponseDocumentJwsKind::class)->tag('heidi.key_bound_artifact');
    $services->set(TokenIssuer::class);
    $services->set(RefreshTokenRevocation::class);
    $services->set(AuthorizationCodeGrant::class)->tag('heidi.oidc.grant');
    $services->set(RefreshTokenGrant::class)->tag('heidi.oidc.grant');
    $services->set(TokenHandler::class)->args([
        '$grants' => tagged_iterator('heidi.oidc.grant'),
    ]);
    $services->set(AccessTokenVerifier::class);
    $services->set(AccessTokenInspector::class);

    // The module: UserInfo, introspection and revocation, discovery, logout
    $services->set(UserInfoHandler::class);
    $services->set(IntrospectionHandler::class);
    $services->set(RevocationHandler::class);
    $services->set(DiscoveryHandler::class)->args([
        '$grants' => tagged_iterator('heidi.oidc.grant'),
    ]);
    $services->set(JwksHandler::class);
    $services->set(EndSessionRequestParser::class);
    $services->set(EndSessionHandler::class);
    $services->set(LogoutTokenIssuer::class);
    $services->set(BackChannelLogout::class);
    $services->set(FrontChannelLogout::class);
    // The two ways of telling a client that a session ended (architecture §4.9): one class per channel,
    // and what is tagged is what the discovery document announces, never an enumeration kept beside it
    $services->set(FrontChannelLogoutRenderer::class)->tag('heidi.logout_channel');
    $services->set(LogoutChannels::class)->args([tagged_iterator('heidi.logout_channel')]);
    $services->alias(ServedLogoutChannelsInterface::class, LogoutChannels::class);
    // how long a logout token stays on its way, from the retries of its lane and the timeout of one send
    $services->set(LogoutTokenDeliveryBudget::class);
    $services->alias(LogoutTokenDeliveryInterface::class, LogoutTokenDeliveryBudget::class);
    $services->set(LogoutTokenJwsKind::class)->tag('heidi.key_bound_artifact');
};
