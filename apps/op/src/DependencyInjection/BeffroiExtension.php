<?php

declare(strict_types=1);

namespace App\DependencyInjection;

use function dirname;
use App\Doctrine\Type\ActorType;
use App\Messenger\MessengerContract;
use App\Doctrine\Type\AddressType;
use App\Doctrine\Type\AuthenticationContextPolicyType;
use App\Doctrine\Type\AuthenticationPredicateType;
use App\Doctrine\Type\SelfServedClaimsType;
use App\Doctrine\Type\LogoutProgressType;
use App\Doctrine\Type\TenantLookType;
use App\Doctrine\Type\AuthenticationProofsType;
use App\Doctrine\Type\BackupCodesType;
use App\Doctrine\Type\BindingMessageType;
use App\Doctrine\Type\BytesType;
use App\Doctrine\Type\PasswordAlgorithmType;
use App\Doctrine\Type\PasswordHashType;
use App\Doctrine\Type\ProfileType;
use App\Doctrine\Type\UserSourceType;
use App\Doctrine\Type\AuthenticationSnapshotType;
use App\Doctrine\Type\ClaimNamesType;
use App\Doctrine\Type\ClaimsRequestType;
use App\Doctrine\Type\ClientSecretType;
use App\Doctrine\Type\CodeChallengeType;
use App\Configuration\BackchannelAuthenticationSection;
use App\Configuration\BackChannelLogoutSection;
use App\Configuration\ClientAuthenticationSection;
use App\Configuration\ClientRegistrationSection;
use App\Configuration\ClientsSection;
use App\Configuration\ExposesParametersInterface;
use App\Configuration\InteractionSection;
use App\Configuration\ConfigurationSectionInterface;
use App\Configuration\DpopSection;
use App\Configuration\GeoipSection;
use App\Configuration\KeysSection;
use App\Configuration\HistorySection;
use App\Configuration\JournalSection;
use App\Configuration\LoadSection;
use App\Configuration\MutualTlsSection;
use App\Configuration\PasswordsSection;
use App\Configuration\RequestObjectsSection;
use App\Configuration\TenantSection;
use App\Configuration\TokensSection;
use App\Configuration\SamlSection;
use App\Configuration\SelfClientSection;
use App\Configuration\TrustedIssuersSection;
use App\Configuration\WebauthnSection;
use App\Configuration\WebPushSection;
use App\Doctrine\Type\ConfirmationType;
use App\Doctrine\Type\AuthorizationDetailsType;
use App\Doctrine\Type\DeviceType;
use App\Doctrine\Type\EmailAddressType;
use App\Doctrine\Type\GeoLocationType;
use App\Doctrine\Type\IssuerType;
use App\Doctrine\Type\KeyConfirmationType;
use App\Doctrine\Type\PasskeyUserHandleType;
use App\Doctrine\Type\RedirectUriType;
use App\Doctrine\Type\RequestContextType;
use App\Doctrine\Type\ResourceIndicatorsType;
use App\Doctrine\Type\ScopesType;
use App\Doctrine\Type\SectorIdentifierType;
use App\Doctrine\Type\SubjectType;
use App\Key\KmsClientPass;
use App\Saml\ServiceProviderEntityIdPass;
use App\Saml\ServiceProvidersPass;
use App\Saml\UpstreamIdentityProvidersPass;
use App\Plane\Plane;
use App\Security\CorePasswordHasher;
use App\Security\RateLimitedAttempts;
use App\Security\SecurityUser;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\AbstractExtension;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

/**
 * The "beffroi:" tree of architecture §5.1, and nothing that decision 0006 forbids: no "insecure_*" key, no
 * compatibility switch. The kernel of the application registers it (BeffroiKernelTrait), and so does the
 * kernel of the suite of the integration.
 */
final class BeffroiExtension extends AbstractExtension
{
    public function configure(DefinitionConfigurator $definition): void
    {
        $children = $definition->rootNode()->children();
        foreach (self::sections() as $section) {
            $section->describe($children);
        }
        $children->end();
    }

    /**
     * By the name the mappings use (architecture §5.3).
     */
    public const array DBAL_TYPES = [
        IssuerType::NAME => IssuerType::class,
        SectorIdentifierType::NAME => SectorIdentifierType::class,
        SubjectType::NAME => SubjectType::class,
        EmailAddressType::NAME => EmailAddressType::class,
        AddressType::NAME => AddressType::class,
        AuthenticationProofsType::NAME => AuthenticationProofsType::class,
        AuthenticationSnapshotType::NAME => AuthenticationSnapshotType::class,
        GeoLocationType::NAME => GeoLocationType::class,
        DeviceType::NAME => DeviceType::class,
        RequestContextType::NAME => RequestContextType::class,
        RedirectUriType::NAME => RedirectUriType::class,
        ScopesType::NAME => ScopesType::class,
        ResourceIndicatorsType::NAME => ResourceIndicatorsType::class,
        AuthorizationDetailsType::NAME => AuthorizationDetailsType::class,
        BindingMessageType::NAME => BindingMessageType::class,
        ClaimsRequestType::NAME => ClaimsRequestType::class,
        ClaimNamesType::NAME => ClaimNamesType::class,
        CodeChallengeType::NAME => CodeChallengeType::class,
        ClientSecretType::NAME => ClientSecretType::class,
        ActorType::NAME => ActorType::class,
        ConfirmationType::NAME => ConfirmationType::class,
        KeyConfirmationType::NAME => KeyConfirmationType::class,
        BytesType::NAME => BytesType::class,
        PasswordAlgorithmType::NAME => PasswordAlgorithmType::class,
        PasswordHashType::NAME => PasswordHashType::class,
        ProfileType::NAME => ProfileType::class,
        UserSourceType::NAME => UserSourceType::class,
        PasskeyUserHandleType::NAME => PasskeyUserHandleType::class,
        AuthenticationContextPolicyType::NAME => AuthenticationContextPolicyType::class,
        AuthenticationPredicateType::NAME => AuthenticationPredicateType::class,
        TenantLookType::NAME => TenantLookType::class,
        SelfServedClaimsType::NAME => SelfServedClaimsType::class,
        BackupCodesType::NAME => BackupCodesType::class,
        LogoutProgressType::NAME => LogoutProgressType::class,
    ];

    /**
     * The passes of the provider, which an extension cannot add itself and a kernel adds for it
     * (BeffroiKernelTrait). The KMS client it seals with is named in its own configuration and
     * registered in the framework's, so nothing but a pass can tell a name that answers from one that
     * does not. The service providers of the tenant are built when the container is compiled, so that a
     * declaration that does not hold together fails the build and not the first login (spec/saml.md
     * section 6.2 step 1), which only a pass can do while leaving aside the values of the environment; the
     * claim of a mapping, which needs the claims providers built, is checked by MappedClaimsWarmer right
     * after, in the same build.
     */
    public static function addCompilerPasses(ContainerBuilder $container): void
    {
        $container->addCompilerPass(new KmsClientPass());
        $container->addCompilerPass(new ServiceProvidersPass());
        $container->addCompilerPass(new ServiceProviderEntityIdPass());
        $container->addCompilerPass(new UpstreamIdentityProvidersPass());
    }

    /**
     * Doctrine gets the mappings, the types and the migrations of the provider (architecture §5.3); the
     * security component gets the hasher of its users (§5.4); the rate limiter gets the limiter of the
     * attempts at a code (§3.4), a rule of the core the application does not tune. The firewall is the
     * application's to declare, and what it names of this extension is a container parameter set here,
     * before any extension is loaded: the kernel registers this extension after the one of SecurityBundle,
     * and a firewall resolves the parameters it names when its own extension is loaded (issue #282).
     */
    public function prependExtension(ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $configs = $builder->getExtensionConfig($this->getAlias());
        foreach (self::sections() as $section) {
            if ($section instanceof ExposesParametersInterface) {
                foreach ($section->parameters($configs) as $name => $value) {
                    $builder->setParameter($name, $value);
                }
            }
        }
        $applicationDir = dirname(__DIR__, 2);
        if ($builder->hasExtension('doctrine')) {
            $builder->prependExtensionConfig('doctrine', [
                'dbal' => [
                    'types' => self::DBAL_TYPES,
                ],
                'orm' => [
                    'mappings' => [
                        'BeffroiCore' => [
                            'type' => 'xml',
                            'is_bundle' => false,
                            'dir' => $applicationDir . '/config/beffroi/doctrine/core',
                            'prefix' => 'Beffroi\\Core\\Domain',
                            'alias' => 'BeffroiCore',
                        ],
                        'BeffroiOidc' => [
                            'type' => 'xml',
                            'is_bundle' => false,
                            'dir' => $applicationDir . '/config/beffroi/doctrine/oidc',
                            'prefix' => 'Beffroi\\Oidc\\Domain',
                            'alias' => 'BeffroiOidc',
                        ],
                        'BeffroiSaml' => [
                            'type' => 'xml',
                            'is_bundle' => false,
                            'dir' => $applicationDir . '/config/beffroi/doctrine/saml',
                            'prefix' => 'Beffroi\\Saml\\Domain',
                            'alias' => 'BeffroiSaml',
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
            // the keys of the clients, the keys of the issuers a tenant trusts, the assertions of a client,
            // the assertions of a trusted issuer and
            // the software statements already seen, each in a pool of its own, the request objects already seen,
            // what DPoP remembers of a proof and what each budget of a load has been asked for live in
            // pools of their own, so that a deployment can point them at a shared store without
            // touching the rest of its cache
            $builder->prependExtensionConfig('framework', [
                'cache' => [
                    'pools' => [
                        'beffroi.client_keys' => [
                            'adapter' => 'cache.app',
                        ],
                        'beffroi.issuer_keys' => [
                            'adapter' => 'cache.app',
                        ],
                        'beffroi.client_assertions' => [
                            'adapter' => 'cache.app',
                        ],
                        'beffroi.issuer_assertions' => [
                            'adapter' => 'cache.app',
                        ],
                        'beffroi.software_statements' => [
                            'adapter' => 'cache.app',
                        ],
                        'beffroi.request_objects' => [
                            'adapter' => 'cache.app',
                        ],
                        'beffroi.dpop' => [
                            'adapter' => 'cache.app',
                        ],
                        'beffroi.load' => [
                            'adapter' => 'cache.app',
                        ],
                    ],
                ],
            ]);
        }
        // The three buses, their middleware and where each marker is sent are the contract of this
        // provider and not a preference of an operator (issue #456, architecture §5.6): an installation
        // that wires them itself and turns the default middleware off or gets "doctrine_transaction" wrong
        // breaks the asynchronous half of the provider, quietly. What is left to an application is its
        // transports, and the lanes default to the database so that a new installation needs no broker.
        if ($builder->hasExtension('messenger')) {
            if (! $builder->hasParameter('env(' . MessengerContract::DSN_ENVIRONMENT_VARIABLE . ')')) {
                $builder->setParameter('env(' . MessengerContract::DSN_ENVIRONMENT_VARIABLE . ')', MessengerContract::DEFAULT_DSN);
            }
            $builder->prependExtensionConfig('messenger', MessengerContract::configuration());
        }
        // The recurring messages of the schedule are routed by their class like every other message, and
        // not handled inside the worker that ticks: the worker that holds the clock only says when.
        if ($builder->hasExtension('scheduler')) {
            $builder->prependExtensionConfig('scheduler', [
                'use_messenger_routing' => true,
            ]);
        }
        if ($builder->hasExtension('doctrine_migrations')) {
            $builder->prependExtensionConfig('doctrine_migrations', [
                'migrations_paths' => [
                    'DoctrineMigrations' => $applicationDir . '/migrations',
                ],
            ]);
        }
    }

    /**
     * Whether the kernel runs in debug. A container built without a kernel, which is what a unit test of
     * this extension builds, is not one.
     */
    private static function isDebug(ContainerBuilder $builder): bool
    {
        return $builder->hasParameter('kernel.debug') && $builder->getParameter('kernel.debug') === true;
    }

    /**
     * @param array<array-key, mixed> $config
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $container->import('../../config/beffroi/services.php');
        // the panel of the provider is a debug tool and nothing else: it is wired when the kernel runs
        // in debug, and a deployment cannot switch it on (issue #152)
        $debug = self::isDebug($builder);
        if ($debug) {
            $container->import('../../config/beffroi/profiler.php');
        }

        if (! $builder->hasParameter('env(BEFFROI_PLANE)')) {
            $builder->setParameter('env(BEFFROI_PLANE)', Plane::All->value);
        }

        $services = $container->services();
        foreach (self::sections() as $section) {
            $section->load($config, $services, $debug);
        }
    }

    /**
     * The capabilities this extension wires, in the order the configuration reference publishes them. It is
     * a list of classes and it lives here because there is nowhere else it could: a configuration tree is
     * built before any service exists, so nothing can be asked for the sections the way the provider asks
     * for its grants or its confirmation kinds.
     *
     * @return list<ConfigurationSectionInterface>
     */
    private static function sections(): array
    {
        return [
            new TenantSection(),
            new KeysSection(),
            new WebauthnSection(),
            new MutualTlsSection(),
            new TokensSection(),
            new LoadSection(),
            new JournalSection(),
            new HistorySection(),
            new GeoipSection(),
            new PasswordsSection(),
            new InteractionSection(),
            new BackChannelLogoutSection(),
            new BackchannelAuthenticationSection(),
            new WebPushSection(),
            new ClientAuthenticationSection(),
            new RequestObjectsSection(),
            new DpopSection(),
            new TrustedIssuersSection(),
            new ClientsSection(),
            new SelfClientSection(),
            new ClientRegistrationSection(),
            new SamlSection(),
        ];
    }
}
