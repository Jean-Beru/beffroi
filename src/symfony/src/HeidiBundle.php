<?php

declare(strict_types=1);

namespace Heidi\Bundle;

use function is_a;
use function dirname;
use Heidi\Bundle\Doctrine\Type\AddressType;
use Heidi\Bundle\Doctrine\Type\AuthenticationContextPolicyType;
use Heidi\Bundle\Doctrine\Type\AuthenticationProofsType;
use Heidi\Bundle\Doctrine\Type\BackupCodesType;
use Heidi\Bundle\Doctrine\Type\BytesType;
use Heidi\Bundle\Doctrine\Type\NeedsPasswordAlgorithmsInterface;
use Heidi\Bundle\Doctrine\Type\PasswordAlgorithmType;
use Heidi\Core\Port\PasswordAlgorithmsInterface;
use Heidi\Bundle\Doctrine\Type\AuthenticationSnapshotType;
use Heidi\Bundle\Doctrine\Type\ClaimsRequestType;
use Heidi\Bundle\Doctrine\Type\CodeChallengeType;
use Heidi\Bundle\Configuration\BackChannelLogoutSection;
use Heidi\Bundle\Configuration\ClientAuthenticationSection;
use Heidi\Bundle\Configuration\ClientsSection;
use Heidi\Bundle\Configuration\ConfigurationSectionInterface;
use Heidi\Bundle\Configuration\DpopSection;
use Heidi\Bundle\Configuration\KeysSection;
use Heidi\Bundle\Configuration\LoadSection;
use Heidi\Bundle\Configuration\MutualTlsSection;
use Heidi\Bundle\Configuration\RequestObjectsSection;
use Heidi\Bundle\Configuration\TenantSection;
use Heidi\Bundle\Configuration\TokensSection;
use Heidi\Bundle\Configuration\WebauthnSection;
use Heidi\Bundle\Doctrine\Type\ConfirmationType;
use Heidi\Bundle\Doctrine\Type\NeedsConfirmationReaderInterface;
use Heidi\Oidc\Port\ConfirmationReaderInterface;
use Heidi\Bundle\Doctrine\Type\DeviceType;
use Heidi\Bundle\Doctrine\Type\EmailAddressType;
use Heidi\Bundle\Doctrine\Type\GeoLocationType;
use Heidi\Bundle\Doctrine\Type\IssuerType;
use Heidi\Bundle\Doctrine\Type\KeyConfirmationType;
use Heidi\Bundle\Doctrine\Type\PasskeyUserHandleType;
use Heidi\Bundle\Doctrine\Type\RedirectUriType;
use Heidi\Bundle\Doctrine\Type\ResourceIndicatorsType;
use Heidi\Bundle\Doctrine\Type\ScopesType;
use Heidi\Bundle\Doctrine\Type\SubjectType;
use Heidi\Bundle\Key\KmsClientPass;
use Heidi\Bundle\Plane\Plane;
use Heidi\Bundle\Security\CorePasswordHasher;
use Heidi\Bundle\Security\RateLimitedAttempts;
use Heidi\Bundle\Security\SecurityUser;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Kernel\AbstractBundle;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

/**
 * The configuration of architecture §5.1, and nothing that decision 0006 forbids: no "insecure_*" key, no
 * compatibility switch.
 */
final class HeidiBundle extends AbstractBundle
{
    protected string $extensionAlias = 'heidi';

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
        SubjectType::NAME => SubjectType::class,
        EmailAddressType::NAME => EmailAddressType::class,
        AddressType::NAME => AddressType::class,
        AuthenticationProofsType::NAME => AuthenticationProofsType::class,
        AuthenticationSnapshotType::NAME => AuthenticationSnapshotType::class,
        GeoLocationType::NAME => GeoLocationType::class,
        DeviceType::NAME => DeviceType::class,
        RedirectUriType::NAME => RedirectUriType::class,
        ScopesType::NAME => ScopesType::class,
        ResourceIndicatorsType::NAME => ResourceIndicatorsType::class,
        ClaimsRequestType::NAME => ClaimsRequestType::class,
        CodeChallengeType::NAME => CodeChallengeType::class,
        ConfirmationType::NAME => ConfirmationType::class,
        KeyConfirmationType::NAME => KeyConfirmationType::class,
        BytesType::NAME => BytesType::class,
        PasswordAlgorithmType::NAME => PasswordAlgorithmType::class,
        PasskeyUserHandleType::NAME => PasskeyUserHandleType::class,
        AuthenticationContextPolicyType::NAME => AuthenticationContextPolicyType::class,
        BackupCodesType::NAME => BackupCodesType::class,
    ];

    /**
     * The types that read a wiring back are told what the deployment is wired with, as soon as the
     * container can answer: which algorithm a stored password hash names, which kind of confirmation a
     * stored "cnf" names. It goes to the class and not to an instance: Doctrine builds its types itself,
     * when a connection is first made, so no instance of one exists while the bundles boot. A deployment
     * has one wiring, and a kernel booted after another hands over the same one.
     */
    public function boot(): void
    {
        $container = $this->container;
        if ($container === null) {
            return;
        }
        $algorithms = $container->has('heidi.password_algorithms') ? $container->get('heidi.password_algorithms') : null;
        $confirmations = $container->has('heidi.confirmations') ? $container->get('heidi.confirmations') : null;
        foreach (self::DBAL_TYPES as $class) {
            if ($algorithms instanceof PasswordAlgorithmsInterface && is_a($class, NeedsPasswordAlgorithmsInterface::class, true)) {
                $class::resolveWith($algorithms);
            }
            if ($confirmations instanceof ConfirmationReaderInterface && is_a($class, NeedsConfirmationReaderInterface::class, true)) {
                $class::resolveWith($confirmations);
            }
        }
    }

    /**
     * The one pass of the bundle: the KMS client it seals with is named in its own configuration and
     * registered in the framework's, so nothing but a pass can tell a name that answers from one that
     * does not.
     */
    public function build(ContainerBuilder $container): void
    {
        parent::build($container);

        $container->addCompilerPass(new KmsClientPass());
    }

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
            // the keys of the clients, the assertions already seen, what DPoP remembers of a proof and
            // what each budget of a load has been asked for live in pools of their own, so that a
            // deployment can point them at a shared store without touching the rest of its cache
            $builder->prependExtensionConfig('framework', [
                'cache' => [
                    'pools' => [
                        'heidi.client_keys' => [
                            'adapter' => 'cache.app',
                        ],
                        'heidi.client_assertions' => [
                            'adapter' => 'cache.app',
                        ],
                        'heidi.dpop' => [
                            'adapter' => 'cache.app',
                        ],
                        'heidi.load' => [
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
        $container->import('../config/services.php');
        // the panel of the provider is a debug tool and nothing else: it is wired when the kernel runs
        // in debug, and a deployment cannot switch it on (issue #152)
        $debug = self::isDebug($builder);
        if ($debug) {
            $container->import('../config/profiler.php');
        }

        if (! $builder->hasParameter('env(HEIDI_PLANE)')) {
            $builder->setParameter('env(HEIDI_PLANE)', Plane::All->value);
        }

        $services = $container->services();
        foreach (self::sections() as $section) {
            $section->load($config, $services, $debug);
        }
    }

    /**
     * The capabilities this bundle wires, in the order the configuration reference publishes them. It is
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
            new BackChannelLogoutSection(),
            new ClientAuthenticationSection(),
            new RequestObjectsSection(),
            new DpopSection(),
            new ClientsSection(),
        ];
    }
}
