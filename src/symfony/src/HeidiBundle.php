<?php

declare(strict_types=1);

namespace Heidi\Bundle;

use function array_column;
use DateInterval;
use function dirname;
use Heidi\Bundle\Doctrine\Type\AddressType;
use Heidi\Bundle\Doctrine\Type\AuthenticationContextPolicyType;
use Heidi\Bundle\Doctrine\Type\AuthenticationProofsType;
use Heidi\Bundle\Doctrine\Type\BackupCodesType;
use Heidi\Bundle\Doctrine\Type\BytesType;
use Heidi\Bundle\Doctrine\Type\ClaimsRequestType;
use Heidi\Bundle\Doctrine\Type\CodeChallengeType;
use Heidi\Bundle\Doctrine\Type\DeviceType;
use Heidi\Bundle\Doctrine\Type\EmailAddressType;
use Heidi\Bundle\Doctrine\Type\GeoLocationType;
use Heidi\Bundle\Doctrine\Type\IssuerType;
use Heidi\Bundle\Doctrine\Type\PasskeyUserHandleType;
use Heidi\Bundle\Doctrine\Type\RedirectUriType;
use Heidi\Bundle\Doctrine\Type\ScopesType;
use Heidi\Bundle\Doctrine\Type\SubjectType;
use Heidi\Bundle\Key\FileSigningKeyRepository;
use Heidi\Bundle\Key\StagingDelay;
use Heidi\Bundle\Plane\Plane;
use Heidi\Bundle\Security\CorePasswordHasher;
use Heidi\Bundle\Security\RateLimitedAttempts;
use Heidi\Bundle\Security\SecurityUser;
use Heidi\Bundle\Tenant\TenantFactory;
use Heidi\Bundle\Webauthn\FileMetadataBlobStore;
use Heidi\Core\Application\Key\SigningKeyRotator;
use Heidi\Core\Bridge\KeyManagement\EnvelopeKeySealer;
use Heidi\Core\Bridge\KeyManagement\EnvelopeSecretSealer;
use Heidi\Core\Domain\Key\SignatureAlgorithm;
use Heidi\Core\Domain\Session\AuthenticationContextClass;
use Heidi\Core\Domain\Session\AuthenticationPredicate;
use Heidi\Oidc\Application\Authorization\AuthorizationHandler;
use Heidi\Oidc\Application\Discovery\JwksHandler;
use Heidi\Oidc\Application\Token\AuthorizationCodeGrant;
use Heidi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Heidi\Oidc\Application\Token\JwtIdTokenIssuer;
use Heidi\Oidc\Application\Token\OpaqueAccessTokenIssuer;
use Heidi\Oidc\Application\Token\TokenIssuer;
use Heidi\Oidc\Bridge\Configuration\ConfigurationClientRepository;
use Heidi\Oidc\Domain\Client\AccessTokenFormat;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\Client\TokenEndpointAuthMethod;
use function is_array;
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
            ->arrayNode('clients')
            ->info('The clients of the tenant, keyed by client identifier. A secret is hashed when the client is loaded and never kept in clear.')
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
            ->enumNode('token_endpoint_auth_method')
            ->values(array_column(TokenEndpointAuthMethod::cases(), 'value'))
            ->defaultValue(TokenEndpointAuthMethod::ClientSecretBasic->value)
            ->end()
            ->booleanNode('requires_consent')
            ->info('Consent is the rule; a first-party application is the named exception.')
            ->defaultTrue()
            ->end()
            ->booleanNode('requires_pkce')
            ->info('PKCE S256 is the rule; a confidential client that cannot send a code_challenge is the named exception of decision 0008, refused for a public client. A challenge the client sends is verified all the same.')
            ->defaultTrue()
            ->end()
            ->enumNode('id_token_signed_response_alg')
            ->values(array_column(SignatureAlgorithm::cases(), 'value'))
            ->defaultValue(SignatureAlgorithm::RS256->value)
            ->end()
            ->enumNode('access_token_format')
            ->info('The shape of the access tokens: "jwt" (RFC 9068, verified offline against the JWK Set) or "opaque" (a reference the resource server introspects, RFC 7662, revocable at once). Per client, nothing global.')
            ->values(array_column(AccessTokenFormat::cases(), 'value'))
            ->defaultValue(AccessTokenFormat::Jwt->value)
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
        // derived at runtime, once the environment placeholders are numbers
        $services->get(SigningKeyRotator::class)
            ->arg('$stagingDelay', inline_service(DateInterval::class)
                ->factory(StagingDelay::interval(...))
                ->args([isset($keys['staging_delay']) ? self::integer($keys, 'staging_delay') : null, self::integer($keys, 'jwks_max_age')]));

        $services->get(AuthorizationHandler::class)
            ->arg('$codeLifetime', self::seconds($tokens, 'authorization_code_ttl'));
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
