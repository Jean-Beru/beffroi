<?php

declare(strict_types=1);

use Heidi\Bundle\Doctrine\Listener\ClientResolver;
use Heidi\Bundle\Doctrine\Repository\DoctrineAccessTokenRepository;
use Heidi\Bundle\Doctrine\Repository\DoctrineAuthenticationSessionRepository;
use Heidi\Bundle\Doctrine\Repository\DoctrineAuthorizationCodeRepository;
use Heidi\Bundle\Doctrine\Repository\DoctrineConsentRepository;
use Heidi\Bundle\Doctrine\Repository\DoctrineCredentialRepository;
use Heidi\Bundle\Doctrine\Repository\DoctrineInteractionRepository;
use Heidi\Bundle\Doctrine\Repository\DoctrineRefreshTokenRepository;
use Heidi\Bundle\Doctrine\Repository\DoctrineUserRepository;
use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Doctrine\TenantSynchronizer;
use Heidi\Bundle\Http\AuthorizationResponder;
use Heidi\Bundle\Http\BrowserSession;
use Heidi\Bundle\Http\InteractionLocale;
use Heidi\Bundle\Http\InteractionPages;
use Heidi\Bundle\Http\PasskeyOptionsStore;
use Heidi\Bundle\Http\PasskeysPage;
use Heidi\Bundle\Http\PendingLoginStore;
use Heidi\Bundle\Http\QrCode;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Bundle\Http\TotpProvisioningSealer;
use Heidi\Bundle\Http\TotpProvisioningStore;
use Heidi\Bundle\Http\TwoFactorPage;
use Heidi\Bundle\Key\FileSigningKeyRepository;
use Heidi\Bundle\Messenger\EventBusDispatcher;
use Heidi\Bundle\Plane\Plane;
use Heidi\Bundle\Plane\PlaneRequestListener;
use Heidi\Bundle\Routing\RouterEndpointLocator;
use Heidi\Bundle\Scheduler\HeidiSchedule;
use Heidi\Bundle\Security\CorePasswordHasher;
use Heidi\Bundle\Security\IdentityUserProvider;
use Heidi\Bundle\Security\InteractionLoginHandler;
use Heidi\Bundle\Security\LoginFailureListener;
use Heidi\Bundle\Security\LoginSuccessListener;
use Heidi\Bundle\Security\PasskeyLoginAuthenticator;
use Heidi\Bundle\Security\PassportProofs;
use Heidi\Bundle\Security\RateLimitedCodeAttempts;
use Heidi\Bundle\Security\SecondFactorGate;
use Heidi\Bundle\Security\TotpLoginAuthenticator;
use Heidi\Bundle\Security\UserChecker;
use Heidi\Bundle\Tenant\TenantFactory;
use Heidi\Core\Application\Authentication\PasswordAuthenticator;
use Heidi\Core\Application\Authentication\SecondFactorRequirement;
use Heidi\Core\Application\Authentication\SessionOpener;
use Heidi\Core\Application\Authentication\SessionTerminator;
use Heidi\Core\Application\Credential\CredentialRevocation;
use Heidi\Core\Application\Identity\UserProvisioner;
use Heidi\Core\Application\Key\SigningKeyRotator;
use Heidi\Core\Application\Passkey\PasskeyAuthentication;
use Heidi\Core\Application\Passkey\PasskeyEnrolment;
use Heidi\Core\Application\Totp\ActiveTotp;
use Heidi\Core\Application\Totp\TotpAuthentication;
use Heidi\Core\Application\Totp\TotpCodeMatcher;
use Heidi\Core\Application\Totp\TotpEnrolment;
use Heidi\Core\Bridge\JwtFramework\JwtFrameworkJwsSigner;
use Heidi\Core\Bridge\JwtFramework\JwtFrameworkJwsVerifier;
use Heidi\Core\Bridge\JwtFramework\JwtFrameworkKeyPairGenerator;
use Heidi\Core\Bridge\Key\SealedKeyProvider;
use Heidi\Core\Bridge\KeyManagement\EnvelopeKeySealer;
use Heidi\Core\Bridge\KeyManagement\EnvelopeSecretSealer;
use Heidi\Core\Bridge\Null\NullGeoLocator;
use Heidi\Core\Bridge\Null\NullUserAgentParser;
use Heidi\Core\Bridge\Otphp\OtphpTotpAlgorithm;
use Heidi\Core\Bridge\Password\NativePasswordHasher;
use Heidi\Core\Bridge\Password\PasswordHasherRegistry;
use Heidi\Core\Bridge\Webauthn\WebauthnCeremonies;
use Heidi\Core\Bridge\Webauthn\WebauthnPasskeyAuthenticator;
use Heidi\Core\Bridge\Webauthn\WebauthnPasskeyRegistrar;
use Heidi\Core\Port\AuthenticationSessionRepositoryInterface;
use Heidi\Core\Port\CodeAttemptLimiterInterface;
use Heidi\Core\Port\CredentialRepositoryInterface;
use Heidi\Core\Port\GeoLocatorInterface;
use Heidi\Core\Port\JwsSignerInterface;
use Heidi\Core\Port\JwsVerifierInterface;
use Heidi\Core\Port\KeyPairGeneratorInterface;
use Heidi\Core\Port\KeySealerInterface;
use Heidi\Core\Port\PasskeyAuthenticatorInterface;
use Heidi\Core\Port\PasskeyRegistrarInterface;
use Heidi\Core\Port\PasswordHasherInterface;
use Heidi\Core\Port\SecretSealerInterface;
use Heidi\Core\Port\SigningKeyProviderInterface;
use Heidi\Core\Port\SigningKeyRepositoryInterface;
use Heidi\Core\Port\TotpAlgorithmInterface;
use Heidi\Core\Port\UserAgentParserInterface;
use Heidi\Core\Port\UserRepositoryInterface;
use Heidi\Oidc\Application\Authorization\AuthorizationHandler;
use Heidi\Oidc\Application\Authorization\AuthorizationRequestParser;
use Heidi\Oidc\Application\Authorization\IdTokenHintVerifier;
use Heidi\Oidc\Application\Claims\PublicSubjectIdentifierResolver;
use Heidi\Oidc\Application\Claims\StandardClaimsProvider;
use Heidi\Oidc\Application\Client\ClientAuthenticator;
use Heidi\Oidc\Application\Discovery\DiscoveryHandler;
use Heidi\Oidc\Application\Discovery\JwksHandler;
use Heidi\Oidc\Application\EndSession\EndSessionHandler;
use Heidi\Oidc\Application\EndSession\EndSessionRequestParser;
use Heidi\Oidc\Application\Introspection\IntrospectionHandler;
use Heidi\Oidc\Application\Key\AccessTokenJwsKind;
use Heidi\Oidc\Application\Key\IdTokenJwsKind;
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
use Heidi\Oidc\Domain\Client\AccessTokenFormat;
use Heidi\Oidc\Port\AccessTokenIssuerInterface;
use Heidi\Oidc\Port\AccessTokenRepositoryInterface;
use Heidi\Oidc\Port\AuthorizationCodeRepositoryInterface;
use Heidi\Oidc\Port\ClaimsProviderInterface;
use Heidi\Oidc\Port\ClientRepositoryInterface;
use Heidi\Oidc\Port\ConsentRepositoryInterface;
use Heidi\Oidc\Port\EndpointLocatorInterface;
use Heidi\Oidc\Port\IdTokenIssuerInterface;
use Heidi\Oidc\Port\InteractionRepositoryInterface;
use Heidi\Oidc\Port\ProvableMethodsInterface;
use Heidi\Oidc\Port\RefreshTokenRepositoryInterface;
use Heidi\Oidc\Port\SubjectIdentifierResolverInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\tagged_iterator;

/*
 * Every service of the core, of the module and of the bundle, autowired, the ports aliased to their one
 * implementation (architecture §3.4, §4.11, §5.2 to §5.4).
 */
return static function (ContainerConfigurator $container): void {
    $services = $container->services();
    $services->defaults()
        ->autowire()
        ->autoconfigure()
        ->private()
        // the core announces in PSR-14; what listens is the event bus, never the dispatcher of the kernel
        ->bind(EventDispatcherInterface::class, service(EventBusDispatcher::class));

    // The bundle
    $services->set(EventBusDispatcher::class)
        ->args([service('event.bus')]);
    $services->set(PlaneRequestListener::class)
        ->args(['%env(enum:' . Plane::class . ':HEIDI_PLANE)%']);
    $services->set(TenantFactory::class);

    // The bundle: the two planes (architecture §5.2)
    $services->load('Heidi\\Bundle\\Controller\\', '../src/Controller/');
    $services->set(RequestContextFactory::class);
    $services->set(BrowserSession::class);
    $services->set(InteractionPages::class);
    $services->set(InteractionLocale::class)
        ->args([
            '$enabledLocales' => '%kernel.enabled_locales%',
            '$defaultLocale' => '%kernel.default_locale%',
        ]);
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

    // The bundle: the console (architecture §5.5)
    $services->load('Heidi\\Bundle\\Command\\', '../src/Command/');

    // The bundle: the handlers of its own messages and what time does on its own (architecture §5.6)
    $services->load('Heidi\\Bundle\\MessageHandler\\', '../src/MessageHandler/');
    $services->set(HeidiSchedule::class);

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
    // what the logins of the firewall prove, read by the listener and announced by the discovery (decision 0010)
    $services->set(PassportProofs::class);
    $services->alias(ProvableMethodsInterface::class, PassportProofs::class);
    // the attempts at a code, counted by the limiter the bundle declares in the framework (architecture §3.4)
    $services->set(RateLimitedCodeAttempts::class)
        ->args([service('limiter.' . RateLimitedCodeAttempts::LIMITER)]);
    $services->alias(CodeAttemptLimiterInterface::class, RateLimitedCodeAttempts::class);

    // The bundle: persistence (architecture §5.3); no service holds a Tenant, an entity is not a service
    $services->set(TenantProvider::class)
        ->tag('kernel.reset', [
            'method' => 'reset',
        ])
        ->tag('doctrine.event_listener', [
            'event' => 'onClear',
        ]);
    $services->set(TenantSynchronizer::class);
    $services->set(ClientResolver::class)
        ->tag('doctrine.orm.entity_listener');
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
    $services->set(FileSigningKeyRepository::class);
    $services->alias(SigningKeyRepositoryInterface::class, FileSigningKeyRepository::class);
    $services->set(SealedKeyProvider::class);
    $services->alias(SigningKeyProviderInterface::class, SealedKeyProvider::class);
    $services->set(JwtFrameworkKeyPairGenerator::class);
    $services->alias(KeyPairGeneratorInterface::class, JwtFrameworkKeyPairGenerator::class);
    $services->set(JwtFrameworkJwsSigner::class);
    $services->alias(JwsSignerInterface::class, JwtFrameworkJwsSigner::class);
    $services->set(JwtFrameworkJwsVerifier::class);
    $services->alias(JwsVerifierInterface::class, JwtFrameworkJwsVerifier::class);
    // the modules tag the kinds of JWS they issue, the rotation dates a retirement from them (architecture §3.3)
    $services->set(SigningKeyRotator::class)
        ->args([
            '$issuedJws' => tagged_iterator('heidi.issued_jws'),
        ]);

    // The core: passwords; the hashers of one algorithm (AlgorithmPasswordHasherInterface) are tagged by hand, the registry is the port the use cases see
    $services->set(NativePasswordHasher::class)
        ->tag('heidi.password_hasher');
    $services->set(PasswordHasherRegistry::class)
        ->args([tagged_iterator('heidi.password_hasher')]);
    $services->alias(PasswordHasherInterface::class, PasswordHasherRegistry::class);

    // The core: the WebAuthn ceremonies on webauthn-lib (architecture §3.4)
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
    $services->set(ClientAuthenticator::class);

    // The module: subject and claims
    $services->set(PublicSubjectIdentifierResolver::class);
    $services->alias(SubjectIdentifierResolverInterface::class, PublicSubjectIdentifierResolver::class);
    $services->set(StandardClaimsProvider::class);
    $services->alias(ClaimsProviderInterface::class, StandardClaimsProvider::class);

    // The module: authorization endpoint
    $services->set(AuthorizationRequestParser::class);
    $services->set(IdTokenHintVerifier::class);
    $services->set(AuthorizationHandler::class);

    // The module: token endpoint; the grants are tagged by hand, the issuers named by the format each one writes
    $services->set(JwtAccessTokenIssuer::class);
    $services->set(OpaqueAccessTokenIssuer::class);
    $services->set(AccessTokenIssuer::class)
        ->args([
            '$issuers' => [
                AccessTokenFormat::Jwt->value => service(JwtAccessTokenIssuer::class),
                AccessTokenFormat::Opaque->value => service(OpaqueAccessTokenIssuer::class),
            ],
        ]);
    $services->alias(AccessTokenIssuerInterface::class, AccessTokenIssuer::class);
    $services->set(JwtIdTokenIssuer::class);
    $services->alias(IdTokenIssuerInterface::class, JwtIdTokenIssuer::class);
    $services->set(IdTokenJwsKind::class)
        ->tag('heidi.issued_jws');
    $services->set(AccessTokenJwsKind::class)
        ->tag('heidi.issued_jws');
    $services->set(TokenIssuer::class);
    $services->set(RefreshTokenRevocation::class);
    $services->set(AuthorizationCodeGrant::class)
        ->tag('heidi.oidc.grant');
    $services->set(RefreshTokenGrant::class)
        ->tag('heidi.oidc.grant');
    $services->set(TokenHandler::class)
        ->args([
            '$grants' => tagged_iterator('heidi.oidc.grant'),
        ]);
    $services->set(AccessTokenVerifier::class);
    $services->set(AccessTokenInspector::class);

    // The module: UserInfo, introspection and revocation, discovery, logout
    $services->set(UserInfoHandler::class);
    $services->set(IntrospectionHandler::class);
    $services->set(RevocationHandler::class);
    $services->set(DiscoveryHandler::class)
        ->args([
            '$grants' => tagged_iterator('heidi.oidc.grant'),
        ]);
    $services->set(JwksHandler::class);
    $services->set(EndSessionRequestParser::class);
    $services->set(EndSessionHandler::class);
};
