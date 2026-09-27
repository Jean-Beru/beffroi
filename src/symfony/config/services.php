<?php

declare(strict_types=1);

use Heidi\Oidc\Application\Secret\SecretDrawer;
use Heidi\Oidc\Application\Secret\UserCodeDrawer;
use Heidi\Core\Port\RandomnessInterface;
use Heidi\Core\Bridge\Random\PlatformRandomness;
use Heidi\Bundle\Ciba\QueuedPendingApprovalNotifier;
use Heidi\Bundle\Cache\SeenOnce;
use Heidi\Bundle\Client\ClientAssertionReplayGuard;
use Heidi\Bundle\Trust\IssuerAssertionReplayGuard;
use Heidi\Bundle\Client\RequestObjectReplayGuard;
use Heidi\Bundle\Client\ClientJwksCache;
use Heidi\Bundle\Client\ClientJwksFetcher;
use Heidi\Bundle\Client\RequestObjectFetcher;
use Heidi\Bundle\Doctrine\Listener\ClientResolver;
use Heidi\Bundle\Doctrine\EntityManagers;
use Heidi\Bundle\Doctrine\Repository\DoctrineAccessTokenRepository;
use Heidi\Bundle\Doctrine\Repository\DoctrineAuthenticationSessionRepository;
use Heidi\Bundle\Doctrine\Repository\DoctrineAuthorizationCodeRepository;
use Heidi\Bundle\Doctrine\Repository\DoctrineConsentRepository;
use Heidi\Bundle\Doctrine\Repository\DoctrineCredentialRepository;
use Heidi\Bundle\Doctrine\Repository\DoctrineInteractionRepository;
use Heidi\Bundle\Doctrine\Repository\DoctrinePushedAuthorizationRecordRepository;
use Heidi\Bundle\Doctrine\Repository\DoctrineBackchannelAuthenticationRecordRepository;
use Heidi\Bundle\Doctrine\Repository\DoctrineDeviceAuthorizationRecordRepository;
use Heidi\Bundle\Doctrine\Repository\DoctrineRefreshTokenRepository;
use Heidi\Bundle\Doctrine\Repository\DoctrineLinkedIdentityRepository;
use Heidi\Bundle\Doctrine\Repository\DoctrineUserRepository;
use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Doctrine\TenantSynchronizer;
use Heidi\Bundle\Dpop\CachedDpopNonce;
use Heidi\Bundle\Dpop\CachedDpopProofReplayGuard;
use Heidi\Bundle\EndSession\FrontChannelLogoutRenderer;
use Heidi\Bundle\EndSession\LogoutChannels;
use Heidi\Bundle\EndSession\LogoutTokenDeliveryBudget;
use Heidi\Bundle\Http\AccountAccess;
use Heidi\Bundle\Http\AccountHomePage;
use Heidi\Bundle\Http\Account\AccountSections;
use Heidi\Bundle\Http\Account\PasskeysSection;
use Heidi\Bundle\Http\Account\ProfileSection;
use Heidi\Bundle\Http\Account\ApprovalsSection;
use Heidi\Bundle\Http\Account\ConsentsSection;
use Heidi\Bundle\Http\Account\TwoFactorSection;
use Heidi\Bundle\Http\AuthorizationRequestReader;
use Heidi\Bundle\Http\Decision\ConsentRequiredRenderer;
use Heidi\Bundle\Http\Decision\DecisionRenderers;
use Heidi\Bundle\Http\Decision\GrantedRenderer;
use Heidi\Bundle\Http\Decision\InteractionPage;
use Heidi\Bundle\Http\Decision\LoginRequiredRenderer;
use Heidi\Bundle\Http\FormToken;
use Heidi\Bundle\Http\DeviceApprovalPage;
use Heidi\Bundle\Http\LoginTarget;
use Heidi\Bundle\Http\AuthorizationRequestReaderInterface;
use Heidi\Bundle\Http\AuthorizationResponder;
use Heidi\Bundle\Http\AuthorizationResponderInterface;
use Heidi\Bundle\Http\BrowserSession;
use Heidi\Bundle\Http\InteractionLocale;
use Heidi\Bundle\Locale\ServedLocales;
use Heidi\Bundle\Locale\UserLocale;
use Heidi\Bundle\Http\InteractionPages;
use Heidi\Bundle\Http\ClientNotificationSender;
use Heidi\Bundle\Http\PendingApprovalsPage;
use Heidi\Bundle\Http\LogoutTokenSender;
use Heidi\Bundle\Http\PasskeyOptionsStore;
use Heidi\Bundle\Http\ProfilePage;
use Heidi\Bundle\Http\PasskeysPage;
use Heidi\Bundle\Http\ConsentsPage;
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
use Heidi\Bundle\Load\LoadBudget;
use Heidi\Bundle\Load\LoadRefusal;
use Heidi\Bundle\Load\LoadRefusalListener;
use Heidi\Bundle\Load\OriginLoadListener;
use Heidi\Bundle\Load\RateLimitedClientLoad;
use Heidi\Bundle\MessageHandler\TellUserOfPendingApprovalHandler;
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
use Heidi\Bundle\Security\DatedPasswordCredential;
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
use Heidi\Core\Application\Authentication\AuthenticationRefusal;
use Heidi\Core\Application\Authentication\LoginCompletion;
use Heidi\Core\Application\Authentication\PasswordAuthenticator;
use Heidi\Core\Application\Authentication\SecondFactorRequirement;
use Heidi\Core\Application\Authentication\SessionOpener;
use Heidi\Core\Application\Authentication\SessionTerminator;
use Heidi\Core\Application\Credential\ActiveCredentials;
use Heidi\Core\Application\Credential\CredentialRevocation;
use Heidi\Core\Application\Identity\IdentityLinker;
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
use Heidi\Core\Bridge\Password\Algorithm\Argon2i;
use Heidi\Core\Bridge\Password\Algorithm\Argon2id;
use Heidi\Core\Bridge\Password\Algorithm\Bcrypt;
use Heidi\Core\Bridge\Password\Algorithm\Pbkdf2Sha256;
use Heidi\Core\Bridge\Password\Algorithm\Pbkdf2Sha512;
use Heidi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Heidi\Core\Bridge\Password\NativePasswordHasher;
use Heidi\Core\Bridge\Password\PasswordHasherRegistry;
use Heidi\Core\Bridge\Password\WiredPasswordAlgorithms;
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
use Heidi\Core\Port\PasswordAlgorithmsInterface;
use Heidi\Core\Port\PasswordHasherInterface;
use Heidi\Core\Port\UuidGeneratorInterface;
use Heidi\Core\Port\PublicKeySetProviderInterface;
use Heidi\Core\Port\SecretSealerInterface;
use Heidi\Core\Port\SignatureAlgorithmsInterface;
use Heidi\Core\Port\SigningKeyProviderInterface;
use Heidi\Core\Port\TenantKeyRepositoryInterface;
use Heidi\Core\Port\TotpAlgorithmInterface;
use Heidi\Core\Port\UserAgentParserInterface;
use Heidi\Core\Port\LinkedIdentityRepositoryInterface;
use Heidi\Core\Port\UserRepositoryInterface;
use Heidi\Oidc\Application\Authorization\AuthenticationRequirement;
use Heidi\Oidc\Application\Authorization\AuthorizationCodeIssuer;
use Heidi\Oidc\Application\Authorization\AuthorizationHandler;
use Heidi\Oidc\Application\Authorization\AuthorizationRequestParser;
use Heidi\Oidc\Application\Authorization\IdTokenHintVerifier;
use Heidi\Oidc\Application\Authorization\RequestObjectReader;
use Heidi\Oidc\Application\Authorization\RequestObjectResolver;
use Heidi\Oidc\Application\Authorization\RequestObjectValidator;
use Heidi\Oidc\Application\Authorization\ResponseDocumentIssuer;
use Heidi\Oidc\Application\Claims\PublicSubjectIdentifierResolver;
use Heidi\Oidc\Application\Claims\StandardClaimsProvider;
use Heidi\Oidc\Application\Client\AcceptedAssertionAudiences;
use Heidi\Oidc\Application\Client\ClientAssertionValidator;
use Heidi\Oidc\Application\Client\ClientAuthenticationMethods;
use Heidi\Oidc\Application\Client\ClientAuthenticationRequestParser;
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
use Heidi\Oidc\Application\Discovery\Metadata\ProviderIdentity;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedScopes;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedResponses;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedGrants;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedBackchannelAuthentication;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedDeviceAuthorization;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedAuthenticationContext;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedIdToken;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedUserInfo;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedClientAuthentication;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedClaims;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedRequestObjects;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedPkce;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedRevocation;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedPushedAuthorization;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedIntrospection;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedIssuerParameter;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedLogout;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedMutualTls;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedDpop;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedSignedAuthorizationResponse;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedMutualTlsEndpoints;
use Heidi\Oidc\Application\AuthorizationDetails\ServedAuthorizationDetailTypes;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedAuthorizationDetails;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedProtectedResources;
use Heidi\Oidc\Application\Discovery\AnnouncedAlgorithms;
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
use Heidi\Oidc\Application\Consent\ConsentGranting;
use Heidi\Oidc\Application\Consent\RequiredConsent;
use Heidi\Oidc\Application\Consent\ConsentRevocation;
use Heidi\Oidc\Application\Exchange\PresentedAccessTokenType;
use Heidi\Oidc\Application\Exchange\PresentedTokenTypes;
use Heidi\Oidc\Application\Grant\RecordedGrants;
use Heidi\Oidc\Application\Trust\IssuerAssertionValidator;
use Heidi\Oidc\Application\Ciba\ApprovalAuthenticationRequirement;
use Heidi\Oidc\Application\Ciba\BackchannelApproval;
use Heidi\Oidc\Application\Ciba\BackchannelAuthenticationHandler;
use Heidi\Oidc\Application\Ciba\Hint\IdTokenUserHint;
use Heidi\Oidc\Application\Ciba\Hint\SubjectLoginHint;
use Heidi\Oidc\Application\Ciba\Hint\UsernameLoginHint;
use Heidi\Oidc\Application\Ciba\ServedDeliveryModes;
use Heidi\Oidc\Application\Ciba\SignedBackchannelRequest;
use Heidi\Oidc\Application\Ciba\UserHints;
use Heidi\Oidc\Application\Device\DeviceApproval;
use Heidi\Oidc\Application\Device\DeviceAuthorizationHandler;
use Heidi\Oidc\Application\PushedAuthorization\PushedAuthorizationRequestResolver;
use Heidi\Oidc\Application\Revocation\RevocationHandler;
use Heidi\Oidc\Application\Token\AccessTokenInspector;
use Heidi\Oidc\Application\Token\AccessTokenVerifier;
use Heidi\Oidc\Application\Token\AuthorizationCodeGrant;
use Heidi\Oidc\Application\Token\ClientCredentialsGrant;
use Heidi\Oidc\Application\Token\JwtBearerGrant;
use Heidi\Oidc\Application\Token\TokenExchangeGrant;
use Heidi\Oidc\Application\Token\BackchannelAuthenticationGrant;
use Heidi\Oidc\Application\Token\DeviceCodeGrant;
use Heidi\Oidc\Application\Token\RefreshTokenDue;
use Heidi\Oidc\Application\Token\RequestedAuthorizationDetails;
use Heidi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Heidi\Oidc\Application\Token\Confirmations;
use Heidi\Oidc\Application\Token\JwtAccessTokenVerifier;
use Heidi\Oidc\Application\Token\JwtIdTokenIssuer;
use Heidi\Oidc\Application\Token\OpaqueAccessTokenIssuer;
use Heidi\Oidc\Application\Token\OpaqueAccessTokenVerifier;
use Heidi\Oidc\Application\Token\PresentedAccessTokenParser;
use Heidi\Oidc\Application\Token\RefreshTokenGrant;
use Heidi\Oidc\Application\Token\ServedAccessTokenShapes;
use Heidi\Oidc\Application\Token\ServedGrants;
use Heidi\Oidc\Application\Token\RefreshTokenRevocation;
use Heidi\Oidc\Application\Token\TokenHandler;
use Heidi\Oidc\Application\Token\TokenIssuer;
use Heidi\Oidc\Application\UserInfo\UserInfoHandler;
use Heidi\Oidc\Bridge\Configuration\ConfigurationClientRepository;
use Heidi\Oidc\Bridge\Configuration\ConfigurationTrustedIssuers;
use Heidi\Oidc\Bridge\JwtLibrary\JwtLibraryClientAssertionSecretVerifier;
use Heidi\Oidc\Bridge\JwtLibrary\JwtLibraryCompactJwtReader;
use Heidi\Oidc\Bridge\JwtLibrary\JwtLibraryJweEncrypter;
use Heidi\Oidc\Bridge\JwtLibrary\JwtLibraryJwtKeyVerifier;
use Heidi\Oidc\Bridge\JwtLibrary\JwtLibraryProofKeyVerifier;
use Heidi\Oidc\Bridge\Null\NoDpopNonce;
use Heidi\Oidc\Bridge\Pki\PkiFrameworkCertificateReader;
use Heidi\Oidc\Port\AccessTokenIssuerInterface;
use Heidi\Oidc\Port\AccessTokenRepositoryInterface;
use Heidi\Oidc\Port\ActiveConsentsInterface;
use Heidi\Oidc\Port\AuthorizationCodeRepositoryInterface;
use Heidi\Oidc\Port\CanRevokeGrantsByConsentInterface;
use Heidi\Oidc\Port\RecordedGrantsInterface;
use Heidi\Oidc\Port\CertificateReaderInterface;
use Heidi\Oidc\Port\ClaimsProviderInterface;
use Heidi\Oidc\Port\ClientAssertionReplayGuardInterface;
use Heidi\Oidc\Port\IssuerAssertionReplayGuardInterface;
use Heidi\Oidc\Port\PresentedTokenTypesInterface;
use Heidi\Oidc\Port\TrustedIssuersInterface;
use Heidi\Oidc\Port\RequestObjectReplayGuardInterface;
use Heidi\Oidc\Port\ClientAssertionSecretVerifierInterface;
use Heidi\Oidc\Port\ClientAuthenticationMethodsInterface;
use Heidi\Oidc\Port\ClientJwksCacheInterface;
use Heidi\Oidc\Port\ClientJwksFetcherInterface;
use Heidi\Oidc\Domain\Token\CertificateConfirmationKind;
use Heidi\Oidc\Domain\Token\KeyConfirmationKind;
use Heidi\Oidc\Port\ClientLoadBudgetInterface;
use Heidi\Oidc\Port\ClientRepositoryInterface;
use Heidi\Oidc\Port\AuthorizationDetailsReaderInterface;
use Heidi\Oidc\Port\ConfirmationReaderInterface;
use Heidi\Oidc\Port\ServedTokenSchemesInterface;
use Heidi\Oidc\Port\RegisteredResourcesInterface;
use Heidi\Oidc\Port\RegisteredAccessTokenShapesInterface;
use Heidi\Oidc\Port\ServedAccessTokenShapesInterface;
use Heidi\Oidc\Port\ServedAuthorizationDetailTypesInterface;
use Heidi\Oidc\Port\ServedGrantsInterface;
use Heidi\Oidc\Port\CompactJwtReaderInterface;
use Heidi\Oidc\Port\ConsentRepositoryInterface;
use Heidi\Oidc\Port\CanRevokeAccessTokensByConsentInterface;
use Heidi\Oidc\Port\RefreshTokensOfAConsentInterface;
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
use Heidi\Oidc\Port\PushedAuthorizationRecordRepositoryInterface;
use Heidi\Oidc\Domain\Ciba\PingDelivery;
use Heidi\Oidc\Domain\Ciba\PollDelivery;
use Heidi\Oidc\Port\BackchannelAuthenticationRecordRepositoryInterface;
use Heidi\Oidc\Port\PendingApprovalNotifierInterface;
use Heidi\Oidc\Port\ServedDeliveryModesInterface;
use Heidi\Oidc\Port\DeviceAuthorizationRecordRepositoryInterface;
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
use Symfony\Component\RateLimiter\Storage\CacheStorage;
use function Symfony\Component\DependencyInjection\Loader\Configurator\inline_service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\tagged_iterator;
use Webauthn\MetadataService\CertificateChain\CertificateChainValidator;
use Webauthn\MetadataService\CertificateChain\PhpCertificateChainValidator;
use Webauthn\MetadataService\MetadataStatementRepository;
use Webauthn\MetadataService\StatusReportRepository;
use Heidi\Core\Port\PushSubscriptionRepositoryInterface;
use Heidi\Core\Port\ApplicationServerKeyProviderInterface;
use Heidi\Core\Port\ApplicationServerAlgorithmsInterface;
use Heidi\Core\Bridge\JwtLibrary\JoseApplicationServerAlgorithms;
use Heidi\Core\Bridge\JwtLibrary\Algorithm\Vapid;
use Heidi\Core\Application\Push\PushSubscriptionRevocation;
use Heidi\Core\Application\Push\PushSubscriptionEnrolment;
use Heidi\Bundle\Configuration\WebPushSection;
use Heidi\Bundle\Push\WebPushSender;
use Heidi\Bundle\Http\NotificationsPage;
use Heidi\Bundle\Http\BundleScript;
use Heidi\Bundle\Http\Account\NotificationsSection;
use Heidi\Bundle\Doctrine\Repository\DoctrinePushSubscriptionRepository;
use Heidi\Bundle\Ciba\WebPushApprovalChannel;

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
    $services->set(FormToken::class);
    // where a page of the provider that is not an authorization request sends a browser to sign in, and
    // where the login of the firewall sends it back (RFC 8628 §3.3)
    $services->set(LoginTarget::class);
    $services->set(DeviceApprovalPage::class);
    $services->set(PendingApprovalsPage::class);
    // Reaching a user through the push service of a browser they signed in with (RFC 8030, §5.6): the
    // pages they subscribe on, what leaves this provider, and the channel the lane hands an approval to.
    // The channel and the algorithm of the key are tagged by WebPushSection and only when a deployment
    // names a subject, a channel nobody wired being a channel nobody wanted.
    $services->set(PushSubscriptionEnrolment::class);
    $services->set(PushSubscriptionRevocation::class);
    $services->set(NotificationsPage::class);
    $services->set(WebPushSender::class)->args([
        '$subject' => '',
        '$timeout' => WebPushSection::DEFAULT_TIMEOUT,
    ]);
    $services->set(WebPushApprovalChannel::class);
    $services->set(AccountAccess::class);
    $services->set(BundleScript::class);
    // the pages of the account, in the order they are wired: what the home of the account offers, and the
    // one place a kind of credential is known; a page added to the account is a section beside these and a
    // line here, and neither the home page nor its template is edited
    // first of the sections: every other one says what the account holds, this one says that somebody is
    // waiting on it now, and it is what makes the page of the answers findable at all (BCP 10027 §5.2)
    $services->set(ApprovalsSection::class)->tag('heidi.account_section');
    $services->set(ProfileSection::class)->tag('heidi.account_section');
    $services->set(PasskeysSection::class)->tag('heidi.account_section');
    $services->set(TwoFactorSection::class)->tag('heidi.account_section');
    $services->set(ConsentsSection::class)->tag('heidi.account_section');
    $services->set(NotificationsSection::class)->tag('heidi.account_section');
    $services->set(AccountSections::class)->args([tagged_iterator('heidi.account_section')]);
    $services->set(AccountHomePage::class);
    // the languages this deployment has, read by the pages of the interaction plane and by whatever
    // writes to a user out of any request of theirs: one list, or a translator is asked for a language
    // that has no catalogue (architecture §5.7)
    $services->set(ServedLocales::class)->args([
        '$enabledLocales' => '%kernel.enabled_locales%',
        '$defaultLocale' => '%kernel.default_locale%',
    ]);
    $services->set(UserLocale::class);
    $services->set(InteractionLocale::class);
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

    // One way of answering per decision of the authorization endpoint (architecture §4.3): a decision
    // the provider gains is a renderer beside these and a line here, and nothing reads a class name
    $services->set(InteractionPage::class);
    $services->set(LoginRequiredRenderer::class)->tag('heidi.authorization_decision');
    $services->set(ConsentRequiredRenderer::class)->tag('heidi.authorization_decision');
    $services->set(GrantedRenderer::class)->tag('heidi.authorization_decision');
    $services->set(DecisionRenderers::class)->args([tagged_iterator('heidi.authorization_decision')]);
    $services->set(AuthorizationResponder::class);
    $services->alias(AuthorizationResponderInterface::class, AuthorizationResponder::class);
    // the two resolvers of the authorization endpoint, in the order the protocol gives them (RFC 9126 §4, RFC 9101 §6.1)
    $services->set(AuthorizationRequestReader::class);
    $services->alias(AuthorizationRequestReaderInterface::class, AuthorizationRequestReader::class);
    $services->set(PasskeyOptionsStore::class);
    $services->set(ProfilePage::class);
    $services->set(PasskeysPage::class);
    $services->set(ConsentsPage::class);
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
    // The bundle: what answers a backchannel request when the certification suite is the one waiting for
    // the answer (CIBA Core §10.1), on the same terms as the endpoints above and in the same place in a
    // deployment: a file of routes of its own (config/routes/ciba-conformance.php), development only
    $services->load('Heidi\\Bundle\\Ciba\\Conformance\\', '../src/Ciba/Conformance/');

    // The bundle: the handlers of its own messages and what time does on its own (architecture §5.6)
    $services->load('Heidi\\Bundle\\MessageHandler\\', '../src/MessageHandler/');
    $services->get(QueueLogoutTokenHandler::class)->tag('heidi.logout_channel');
    $services->set(HeidiSchedule::class);
    // what tells a user that something is waiting for them, on the lane rather than in the request the
    // client is waiting on (CIBA Core §7); what carries the word at the end of it is whatever a
    // deployment tagged "heidi.pending_approval_channel", and the bundle tags nothing
    $services->set(QueuedPendingApprovalNotifier::class);
    $services->alias(PendingApprovalNotifierInterface::class, QueuedPendingApprovalNotifier::class);
    $services->get(TellUserOfPendingApprovalHandler::class)->args([
        '$channels' => tagged_iterator('heidi.pending_approval_channel'),
    ]);
    // what carries a logout token to a client, and what says the provider gave up on one (§4.9)
    $services->set(LogoutTokenSender::class);
    // what tells a client that a backchannel request it made has been answered (CIBA Core §10.2)
    $services->set(ClientNotificationSender::class);
    $services->set(LogoutTokenGivenUpListener::class);
    // how long a notification the provider carries to a third party is tried again: the policy the
    // application gives to the transport of that lane, and the one thing that says so
    $services->set(NotificationRetryPolicy::class);

    // The bundle: security (architecture §5.4); the application names these in its firewall
    $services->set(IdentityUserProvider::class);
    $services->set(CorePasswordHasher::class);
    $services->set(UserChecker::class);
    $services->set(InteractionLoginHandler::class);
    $services->set(LoginSuccessListener::class)->args(['$logins' => tagged_iterator('heidi.login')]);
    $services->set(LoginFailureListener::class)->args(['$logins' => tagged_iterator('heidi.login.refusal')]);
    $services->set(PasskeyLoginAuthenticator::class);
    // a password of a user who holds a second factor is held until the code, verified by the second authenticator of the firewall
    $services->set(SecondFactorGate::class);
    $services->set(TotpLoginAuthenticator::class);
    // what the logins of the firewall prove, read by the listener and announced by the discovery (decision 0010):
    // one class per login, and what is tagged is what the provider announces
    // "heidi.login" is every login; "heidi.login.refusal" is those whose refusals the listener
    // announces, the second step announcing its own through the core
    $services->set(DatedPasswordCredential::class);
    $services->set(PasswordLogin::class)->tag('heidi.login')->tag('heidi.login.refusal');
    $services->set(PasskeyLogin::class)->tag('heidi.login')->tag('heidi.login.refusal');
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

    // The bundle: the two budgets that bound a load (decision 0014), the numbers filled in by the
    // configuration and the count kept in a pool of its own, shared by the processes of the OP: what one
    // origin sends, counted on every route of the two planes before any work, and what one authenticated
    // client asks, counted where the module proves its identifier. A refusal is one shape for both.
    $services->set('heidi.load.storage', CacheStorage::class)->args([service('heidi.load')]);
    $services->set('heidi.load.' . LoadBudget::ORIGIN, LoadBudget::class)->args([
        '$name' => LoadBudget::ORIGIN,
        '$storage' => service('heidi.load.storage'),
    ]);
    $services->set('heidi.load.' . LoadBudget::CLIENT, LoadBudget::class)->args([
        '$name' => LoadBudget::CLIENT,
        '$storage' => service('heidi.load.storage'),
    ]);
    $services->set(OriginLoadListener::class)->args([service('heidi.load.' . LoadBudget::ORIGIN)]);
    $services->set(RateLimitedClientLoad::class)->args([service('heidi.load.' . LoadBudget::CLIENT)]);
    $services->alias(ClientLoadBudgetInterface::class, RateLimitedClientLoad::class);
    $services->set(LoadRefusal::class);
    $services->set(LoadRefusalListener::class);

    // The bundle: persistence (architecture §5.3); no service holds a Tenant, an entity is not a service
    $services->set(EntityManagers::class);
    $services->set(TenantProvider::class)->tag('kernel.reset', [
        'method' => 'reset',
    ])->tag('doctrine.event_listener', [
        'event' => 'onClear',
    ]);
    $services->set(TenantSynchronizer::class);
    $services->set(ClientResolver::class)->tag('doctrine.orm.entity_listener');
    $services->set(DoctrineUserRepository::class);
    $services->alias(UserRepositoryInterface::class, DoctrineUserRepository::class);
    // the identities a user has at an upstream provider (decision 0002), which is what the subject of an
    // assertion of a trusted issuer resolves through (RFC 7523 §2.1)
    $services->set(DoctrineLinkedIdentityRepository::class);
    $services->alias(LinkedIdentityRepositoryInterface::class, DoctrineLinkedIdentityRepository::class);
    // the browsers of a user this provider may push to (decision 0002, §5.6)
    $services->set(DoctrinePushSubscriptionRepository::class);
    $services->alias(PushSubscriptionRepositoryInterface::class, DoctrinePushSubscriptionRepository::class);
    $services->set(DoctrineCredentialRepository::class);
    $services->alias(CredentialRepositoryInterface::class, DoctrineCredentialRepository::class);
    $services->set(DoctrineAuthenticationSessionRepository::class);
    $services->alias(AuthenticationSessionRepositoryInterface::class, DoctrineAuthenticationSessionRepository::class);
    $services->set(DoctrineInteractionRepository::class);
    $services->alias(InteractionRepositoryInterface::class, DoctrineInteractionRepository::class);
    // the three stores that carry a grant, each one tagged so that the reader of what a token descends
    // from asks them all and knows no flow by name (architecture §4.6)
    $services->set(DoctrineAuthorizationCodeRepository::class)->tag('heidi.oidc.grant_record');
    $services->alias(AuthorizationCodeRepositoryInterface::class, DoctrineAuthorizationCodeRepository::class);
    // the grants of a session name the clients to tell it ended (Back-Channel Logout 1.0 §2.6)
    $services->alias(LoggedInClientsInterface::class, DoctrineAuthorizationCodeRepository::class);
    $services->set(DoctrinePushedAuthorizationRecordRepository::class);
    $services->alias(PushedAuthorizationRecordRepositoryInterface::class, DoctrinePushedAuthorizationRecordRepository::class);
    $services->set(DoctrineDeviceAuthorizationRecordRepository::class)->tag('heidi.oidc.grant_record');
    $services->alias(DeviceAuthorizationRecordRepositoryInterface::class, DoctrineDeviceAuthorizationRecordRepository::class);
    $services->set(DoctrineBackchannelAuthenticationRecordRepository::class)->tag('heidi.oidc.grant_record');
    $services->alias(BackchannelAuthenticationRecordRepositoryInterface::class, DoctrineBackchannelAuthenticationRecordRepository::class);
    $services->set(DoctrineRefreshTokenRepository::class);
    $services->alias(RefreshTokenRepositoryInterface::class, DoctrineRefreshTokenRepository::class);
    $services->alias(RefreshTokensOfAConsentInterface::class, DoctrineRefreshTokenRepository::class);
    $services->set(DoctrineAccessTokenRepository::class);
    $services->alias(AccessTokenRepositoryInterface::class, DoctrineAccessTokenRepository::class);
    $services->alias(CanRevokeAccessTokensByConsentInterface::class, DoctrineAccessTokenRepository::class);
    $services->set(DoctrineConsentRepository::class);
    $services->alias(ConsentRepositoryInterface::class, DoctrineConsentRepository::class);
    // what the page of the account lists, read past the profiler: it is no interaction
    $services->alias(ActiveConsentsInterface::class, DoctrineConsentRepository::class);

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
    $services->alias(ApplicationServerKeyProviderInterface::class, SealedKeyProvider::class);
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
    // The algorithms of the keys the tenant hands out itself rather than publishing in its JWK Set
    // (RFC 8292 §2): wired by the deployment that reaches its users by push and by no other, so that a
    // deployment that does not draws no such key and has no page that would hand one out (§5.6).
    $services->set(Vapid::class);
    $services->set(JoseApplicationServerAlgorithms::class)->args([tagged_iterator('heidi.application_server_algorithm')]);
    $services->alias(ApplicationServerAlgorithmsInterface::class, JoseApplicationServerAlgorithms::class);
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
    // The algorithms a hash may have been made with, in the order they are wired: the first one is what a
    // new hash is made with, the others are what an import may bring. A new one is a class and a line here.
    $services->set(Argon2id::class)->tag('heidi.password_algorithm');
    $services->set(Argon2i::class)->tag('heidi.password_algorithm');
    $services->set(Bcrypt::class)->tag('heidi.password_algorithm');
    $services->set(Pbkdf2Sha256::class)->tag('heidi.password_algorithm');
    $services->set(Pbkdf2Sha512::class)->tag('heidi.password_algorithm');
    $services->set(WiredPasswordAlgorithms::class)->args([tagged_iterator('heidi.password_algorithm')]);
    $services->alias(PasswordAlgorithmsInterface::class, WiredPasswordAlgorithms::class);
    // Public on purpose: the DBAL types that read a hash back cannot be injected into, and the bundle
    // hands them the wiring when it boots (HeidiBundle::boot()).
    $services->alias('heidi.password_algorithms', PasswordAlgorithmsInterface::class)->public();

    $services->set(NativePasswordHasher::class)->tag('heidi.password_hasher');
    $services->set(PasswordHasherRegistry::class)->args([tagged_iterator('heidi.password_hasher'), service(PasswordAlgorithmsInterface::class)]);
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

    // Where the identifiers of the core come from, as its clock is given to it and not read
    $services->set(SymfonyUuidGenerator::class);
    $services->alias(UuidGeneratorInterface::class, SymfonyUuidGenerator::class);
    // Where the bytes of a drawn value come from, for the same reason and in the same way (issue #245)
    $services->set(PlatformRandomness::class);
    $services->alias(RandomnessInterface::class, PlatformRandomness::class);

    // The core: use cases
    $services->set(PasswordAuthenticator::class);
    $services->set(LoginCompletion::class);
    $services->set(SecondFactorRequirement::class);
    $services->set(PasskeyEnrolment::class);
    $services->set(PasskeyAuthentication::class);
    $services->set(TotpEnrolment::class);
    $services->set(TotpAuthentication::class);
    $services->set(CredentialRevocation::class);
    $services->set(ActiveCredentials::class);
    $services->set(SessionOpener::class);
    $services->set(SessionTerminator::class);
    $services->set(AuthenticationRefusal::class);
    $services->set(UserProvisioner::class);
    // Decision 0002: the one way a row saying a user is a subject at an upstream provider comes to exist
    // outside a flow that receives one; what needs it today is the JWT bearer grant (RFC 7523 §3)
    $services->set(IdentityLinker::class);

    // The module: every value this provider hands out and recognises again is drawn here (issue #245)
    $services->set(SecretDrawer::class);
    // RFC 8628 §3.3: a code read out loud and typed on a phone is not one of those, and is drawn beside them
    $services->set(UserCodeDrawer::class);

    // RFC 9396 §2: one class per type of authorization detail, tagged, and what is tagged is what a
    // request may ask for, what a client may register and what the discovery document announces, never an
    // enumeration kept beside them (issue #98). The bundle wires none: no type of detail is universal, a
    // type says what a client may do to what in the words of one domain, so a deployment that serves rich
    // authorization requests adds the class its own domain needs and tags it here.
    $services->set(ServedAuthorizationDetailTypes::class)->args([tagged_iterator('heidi.oidc.authorization_detail_type')]);
    $services->alias(AuthorizationDetailsReaderInterface::class, ServedAuthorizationDetailTypes::class);
    $services->alias(ServedAuthorizationDetailTypesInterface::class, ServedAuthorizationDetailTypes::class);
    $services->alias('heidi.authorization_detail_types', AuthorizationDetailsReaderInterface::class)->public();

    // The module: clients
    $services->set(ConfigurationClientRepository::class);
    $services->alias(ClientRepositoryInterface::class, ConfigurationClientRepository::class);
    // RFC 9126 §5: whether the document says a request must be pushed is what the registered clients
    // require, read where they are declared and nowhere else (issue #98)
    $services->alias(PushedAuthorizationRequirementInterface::class, ConfigurationClientRepository::class);
    $services->alias(RegisteredResourcesInterface::class, ConfigurationClientRepository::class);
    $services->alias(RegisteredAccessTokenShapesInterface::class, ConfigurationClientRepository::class);
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
    // what arrived at such an endpoint, read once into what the methods read (issue #246): the assertion
    // of RFC 7523 §2.2 included, however many of the wired methods go on to read it
    $services->set(ClientAuthenticationRequestParser::class);
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
    // the names of this provider a client assertion may name in its "aud" (issue #267): the issuer of
    // the tenant, and the two endpoints CIBA Core §7.1 adds for a client registered for a grant that
    // reaches its user itself, read from what the provider serves and from what the client registered
    $services->set(AcceptedAssertionAudiences::class);
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
        inline_service(SeenOnce::class)->args([service('heidi.client_assertions')]),
    ]);
    $services->alias(ClientAssertionReplayGuardInterface::class, ClientAssertionReplayGuard::class);

    // The module: an assertion read as an authorization and not as an authentication (RFC 7523 §2.1). It
    // shares nothing with the reading above: its own registration of who is trusted, its own validator and
    // its own pool of the assertions already seen, so that one reading cannot satisfy the other.
    $services->set(ConfigurationTrustedIssuers::class);
    $services->alias(TrustedIssuersInterface::class, ConfigurationTrustedIssuers::class);
    $services->set(IssuerAssertionValidator::class);
    $services->set(IssuerAssertionReplayGuard::class)->args([
        inline_service(SeenOnce::class)->args([service('heidi.issuer_assertions')]),
    ]);
    $services->alias(IssuerAssertionReplayGuardInterface::class, IssuerAssertionReplayGuard::class);

    // The module: the proof of possession a request carries (RFC 9449), read with the reader every JWT
    // a client signs is read with and verified against the key of its own header, with the algorithms
    // the provider is wired with; the proofs already seen and the nonces it hands out live in a pool
    // the workers share, as the assertions already seen do
    $services->set(JwtLibraryProofKeyVerifier::class)->args([service('heidi.oidc.client_assertion.signature_algorithms')]);
    $services->alias(ProofKeyVerifierInterface::class, JwtLibraryProofKeyVerifier::class);
    $services->set(CachedDpopProofReplayGuard::class)->args([
        inline_service(SeenOnce::class)->args([service('heidi.dpop')]),
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
    // CIBA Core §7.1.1: the "jti" of a backchannel request object is remembered until its "exp", in a
    // pool of its own, so that one signed request is made once (issue #269)
    $services->set(RequestObjectReplayGuard::class)->args([
        inline_service(SeenOnce::class)->args([service('heidi.request_objects')]),
    ]);
    $services->alias(RequestObjectReplayGuardInterface::class, RequestObjectReplayGuard::class);
    $services->set(RequestObjectFetcher::class);
    $services->alias(RequestObjectFetcherInterface::class, RequestObjectFetcher::class);
    $services->set(PushedAuthorizationHandler::class);
    // RFC 8628 §3.1, §3.3: where a client with no browser starts, and what the page its user goes to asks
    $services->set(DeviceAuthorizationHandler::class);
    $services->set(DeviceApproval::class);
    // CIBA Core §7, §10.1: where a client asks for a user it names, and what the page that user answers
    // on asks. One class per way of telling the client its request was answered, tagged, and what is
    // tagged is what a client may register and what the document announces; one class per way a request
    // may name its user, of which the deployment wires the one that reads a "login_hint"
    // (BackchannelAuthenticationSection) and this the one that reads an ID token we issued
    $services->set(PollDelivery::class)->tag('heidi.oidc.ciba_delivery_mode');
    $services->set(PingDelivery::class)->tag('heidi.oidc.ciba_delivery_mode');
    $services->set(ServedDeliveryModes::class)->args([tagged_iterator('heidi.oidc.ciba_delivery_mode')]);
    $services->alias(ServedDeliveryModesInterface::class, ServedDeliveryModes::class);
    $services->set(IdTokenUserHint::class)->tag('heidi.oidc.ciba_user_hint');
    // the two ways of reading a "login_hint" the bundle ships, of which the deployment tags one: two
    // things reading one parameter would be a wiring with two answers to one question
    $services->set(SubjectLoginHint::class);
    $services->set(UsernameLoginHint::class);
    $services->set(UserHints::class)->args([tagged_iterator('heidi.oidc.ciba_user_hint')]);
    $services->set(SignedBackchannelRequest::class);
    $services->set(BackchannelAuthenticationHandler::class);
    // what a backchannel request asks of the authentication of whoever answers it (issue #266)
    $services->set(ApprovalAuthenticationRequirement::class);
    $services->set(BackchannelApproval::class);
    // What a client may still be encrypting to a key of the tenant, which is what holds an encryption key
    // back from retiring: each one reads its lifetime where that lifetime is set (architecture §3.3)
    $services->set(RequestObjectJweKind::class)->tag('heidi.key_bound_artifact');
    $services->set(PushedRequestJweKind::class)->tag('heidi.key_bound_artifact');
    $services->set(IdTokenHintVerifier::class);
    // The authorization endpoint, one subject per class (issue #251): what the authentication of an
    // interaction still needs, whether a consent page is still needed, the code minted when nothing is, and
    // a handler that orchestrates the three and owns the lifecycle of the interaction.
    $services->set(AuthenticationRequirement::class);
    $services->set(AuthorizationCodeIssuer::class);
    $services->set(RequiredConsent::class);
    $services->set(AuthorizationHandler::class);
    $services->set(ConsentGranting::class);
    // and its counterpart: a consent taken back takes back what was issued under it (issue #273)
    $services->set(ConsentRevocation::class);
    // JARM §2.1: what the two signed modes deliver, minted where every other JWS of the tenant is
    $services->set(ResponseDocumentIssuer::class);

    // The module: token endpoint. One class per shape an access token is written in, tagged, and what
    // is tagged is what a client may register and what a signing key still waits for, never an
    // enumeration kept beside them (issue #239). An issuer names the shape it writes and the verifier of
    // that shape answers to the same name; the first tagged one is what a client that names none takes.
    $services->set(JwtAccessTokenIssuer::class)->tag('heidi.oidc.access_token_issuer');
    $services->set(OpaqueAccessTokenIssuer::class)->tag('heidi.oidc.access_token_issuer');
    $services->set(ServedAccessTokenShapes::class)->args([tagged_iterator('heidi.oidc.access_token_issuer')]);
    $services->alias(AccessTokenIssuerInterface::class, ServedAccessTokenShapes::class);
    $services->alias(ServedAccessTokenShapesInterface::class, ServedAccessTokenShapes::class);
    $services->set(JwtIdTokenIssuer::class);
    $services->alias(IdTokenIssuerInterface::class, JwtIdTokenIssuer::class);
    $services->set(IdTokenJwsKind::class)->tag('heidi.key_bound_artifact');
    $services->set(AccessTokenJwsKind::class)->tag('heidi.key_bound_artifact');
    $services->set(ResponseDocumentJwsKind::class)->tag('heidi.key_bound_artifact');
    $services->set(TokenIssuer::class);
    $services->set(RefreshTokenRevocation::class);
    // RFC 6749 §4.1.4: whether a response carries a refresh token, asked once for every grant that may
    $services->set(RefreshTokenDue::class);
    // RFC 9396 §7: what a token request narrows the details of its authorization to, read once for every
    // grant that spends one, as RequestedResources is for the resources beside them
    $services->set(RequestedAuthorizationDetails::class);
    // one class per grant, tagged, and what is tagged is what the token endpoint serves, what a client
    // may register and what the discovery document announces, never an enumeration kept beside them
    // (issue #173). A grant names itself and declares what it makes of a refresh token by the interfaces
    // it implements; the list is read when a question is asked of it, because a grant reads it too.
    $services->set(AuthorizationCodeGrant::class)->tag('heidi.oidc.grant');
    $services->set(RefreshTokenGrant::class)->tag('heidi.oidc.grant');
    $services->set(ClientCredentialsGrant::class)->tag('heidi.oidc.grant');
    $services->set(DeviceCodeGrant::class)->tag('heidi.oidc.grant');
    $services->set(BackchannelAuthenticationGrant::class)->tag('heidi.oidc.grant');
    $services->set(TokenExchangeGrant::class)->tag('heidi.oidc.grant');
    $services->set(JwtBearerGrant::class)->tag('heidi.oidc.grant');
    $services->set(ServedGrants::class)->args([tagged_iterator('heidi.oidc.grant')]);
    $services->alias(ServedGrantsInterface::class, ServedGrants::class);
    // one class per type of token the exchange reads (RFC 8693 §3), tagged, and what is tagged is what a
    // request may present and what a client may register, never an enumeration kept beside them
    $services->set(PresentedAccessTokenType::class)->tag('heidi.oidc.presented_token_type');
    $services->set(PresentedTokenTypes::class)->args([tagged_iterator('heidi.oidc.presented_token_type')]);
    $services->alias(PresentedTokenTypesInterface::class, PresentedTokenTypes::class);
    $services->set(TokenHandler::class);
    // what a token descends from, and what a consent taken back reaches, read across the records every
    // flow of the provider writes (architecture §4.3, §4.6)
    $services->set(RecordedGrants::class)->args([tagged_iterator('heidi.oidc.grant_record')]);
    $services->alias(RecordedGrantsInterface::class, RecordedGrants::class);
    $services->alias(CanRevokeGrantsByConsentInterface::class, RecordedGrants::class);
    $services->set(CertificateConfirmationKind::class)->tag('heidi.oidc.confirmation_kind');
    $services->set(KeyConfirmationKind::class)->tag('heidi.oidc.confirmation_kind');
    $services->set(Confirmations::class)->args([tagged_iterator('heidi.oidc.confirmation_kind')]);
    $services->alias(ConfirmationReaderInterface::class, Confirmations::class);
    $services->alias(ServedTokenSchemesInterface::class, Confirmations::class);
    $services->alias('heidi.confirmations', ConfirmationReaderInterface::class)->public();

    // the other side of a shape: a token this provider writes and cannot read back is refused by the
    // verifier that collects them, where the two wired lists meet
    $services->set(JwtAccessTokenVerifier::class)->tag('heidi.oidc.access_token_verifier');
    $services->set(OpaqueAccessTokenVerifier::class)->tag('heidi.oidc.access_token_verifier');
    $services->set(AccessTokenVerifier::class)->args([tagged_iterator('heidi.oidc.access_token_verifier')]);
    $services->set(AccessTokenInspector::class);
    $services->set(PresentedAccessTokenParser::class);

    // The module: UserInfo, introspection and revocation, discovery, logout
    $services->set(UserInfoHandler::class);
    $services->set(IntrospectionHandler::class);
    $services->set(RevocationHandler::class);
    // What the provider announces is what it is wired with: each specification it implements contributes
    // its own members, in the order the document publishes them, and a capability that arrives is a class
    // here and nothing edited elsewhere (architecture §4.8).
    $services->set(AnnouncedAlgorithms::class);
    $services->set(ProviderIdentity::class)->tag('heidi.oidc.metadata');
    $services->set(AnnouncedScopes::class)->tag('heidi.oidc.metadata');
    $services->set(AnnouncedResponses::class)->tag('heidi.oidc.metadata');
    $services->set(AnnouncedGrants::class)->tag('heidi.oidc.metadata');
    $services->set(AnnouncedAuthenticationContext::class)->tag('heidi.oidc.metadata');
    $services->set(AnnouncedIdToken::class)->tag('heidi.oidc.metadata');
    $services->set(AnnouncedUserInfo::class)->tag('heidi.oidc.metadata');
    $services->set(AnnouncedClientAuthentication::class)->tag('heidi.oidc.metadata');
    $services->set(AnnouncedClaims::class)->tag('heidi.oidc.metadata');
    $services->set(AnnouncedRequestObjects::class)->tag('heidi.oidc.metadata');
    $services->set(AnnouncedPkce::class)->tag('heidi.oidc.metadata');
    $services->set(AnnouncedRevocation::class)->tag('heidi.oidc.metadata');
    $services->set(AnnouncedPushedAuthorization::class)->tag('heidi.oidc.metadata');
    $services->set(AnnouncedDeviceAuthorization::class)->tag('heidi.oidc.metadata');
    $services->set(AnnouncedBackchannelAuthentication::class)->tag('heidi.oidc.metadata');
    $services->set(AnnouncedIntrospection::class)->tag('heidi.oidc.metadata');
    $services->set(AnnouncedIssuerParameter::class)->tag('heidi.oidc.metadata');
    $services->set(AnnouncedLogout::class)->tag('heidi.oidc.metadata');
    $services->set(AnnouncedMutualTls::class)->tag('heidi.oidc.metadata');
    $services->set(AnnouncedDpop::class)->tag('heidi.oidc.metadata');
    $services->set(AnnouncedSignedAuthorizationResponse::class)->tag('heidi.oidc.metadata');
    $services->set(AnnouncedMutualTlsEndpoints::class)->tag('heidi.oidc.metadata');
    $services->set(AnnouncedProtectedResources::class)->tag('heidi.oidc.metadata');
    $services->set(AnnouncedAuthorizationDetails::class)->tag('heidi.oidc.metadata');
    $services->set(DiscoveryHandler::class)->args([
        '$contributors' => tagged_iterator('heidi.oidc.metadata'),
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
