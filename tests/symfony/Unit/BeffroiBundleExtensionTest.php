<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit;

use DateInterval;
use Beffroi\Bundle\BeffroiBundle;
use Beffroi\Bundle\Key\FileTenantKeyRepository;
use Beffroi\Bundle\Key\StagingDelay;
use Beffroi\Bundle\Tenant\TenantFactory;
use Beffroi\Core\Application\Key\TenantKeyRotator;
use Beffroi\Core\Bridge\KeyManagement\EnvelopeKeySealer;
use Beffroi\Oidc\Application\Authorization\AuthorizationCodeIssuer;
use Beffroi\Oidc\Application\Client\Registration\OpenRegistrationAuthorization;
use Beffroi\Oidc\Application\Token\AuthorizationCodeGrant;
use Beffroi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Beffroi\Oidc\Application\Token\JwtAccessTokenVerifier;
use Beffroi\Oidc\Application\Token\JwtIdTokenIssuer;
use Beffroi\Oidc\Application\Token\OpaqueAccessTokenIssuer;
use Beffroi\Oidc\Application\Token\OpaqueAccessTokenVerifier;
use Beffroi\Oidc\Application\Token\TokenIssuer;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationClientRegistrationPolicy;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationClientRepository;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;

/**
 * What the extension hands the services from the configuration, read on the definitions before the
 * container is compiled: the values of "beffroi.tokens" become the DateIntervals of the use cases, the
 * values of "beffroi.keys" and "beffroi.tenant" the arguments of the bridges.
 */
final class BeffroiBundleExtensionTest extends TestCase
{
    #[Test]
    public function theLifetimesOfTheConfigurationReachTheUseCases(): void
    {
        // When
        $container = self::load([
            'tokens' => [
                'authorization_code_ttl' => 45,
                'access_token_ttl' => 300,
                'id_token_ttl' => 120,
                'refresh_token_ttl' => 1000,
                'refresh_token_absolute_ttl' => 2000,
            ],
        ]);

        // Then
        static::assertSame('PT45S', self::interval($container, AuthorizationCodeIssuer::class, '$lifetime'));
        static::assertSame('PT300S', self::interval($container, JwtAccessTokenIssuer::class, '$lifetime'));
        static::assertSame('PT300S', self::interval($container, OpaqueAccessTokenIssuer::class, '$lifetime'));
        static::assertSame('PT120S', self::interval($container, JwtIdTokenIssuer::class, '$lifetime'));
        static::assertSame('PT1000S', self::interval($container, TokenIssuer::class, '$refreshTokenLifetime'));
        static::assertSame('PT2000S', self::interval($container, AuthorizationCodeGrant::class, '$refreshTokenFamilyLifetime'));
    }

    #[Test]
    public function theTenantAndTheKeysReachTheBridges(): void
    {
        // When
        $container = self::load([
            'tenant' => [
                'issuer' => 'https://op.test/tenant-a',
                'slug' => 'tenant-a',
                'name' => 'Tenant A',
            ],
            'keys' => [
                'kms' => 'op',
                'key_id' => 'k',
                'storage' => '/var/lib/beffroi/keys',
            ],
        ]);

        // Then
        $factory = $container->getDefinition(TenantFactory::class);
        static::assertSame('https://op.test/tenant-a', $factory->getArgument('$issuer'));
        static::assertSame('tenant-a', $factory->getArgument('$slug'));
        static::assertSame('Tenant A', $factory->getArgument('$name'));
        static::assertSame('key_management.op', (string) $container->getAlias('beffroi.kms'));
        static::assertSame('k', $container->getDefinition(EnvelopeKeySealer::class)->getArgument('$kmsKeyId'));
        static::assertSame('/var/lib/beffroi/keys', $container->getDefinition(FileTenantKeyRepository::class)->getArgument('$directory'));
    }

    /**
     * Architecture §3.3: the staging delay derives from the JWK Set max-age unless the configuration sets
     * it; the derivation happens at runtime, so that an environment placeholder can stand for either.
     */
    #[Test]
    public function theStagingDelayDerivesFromTheJwksMaxAgeUnlessSet(): void
    {
        // When
        $container = self::load([
            'keys' => [
                'kms' => 'op',
                'key_id' => 'k',
                'jwks_max_age' => 120,
            ],
        ]);

        // Then
        $delay = $container->getDefinition(TenantKeyRotator::class)->getArgument('$stagingDelay');
        static::assertInstanceOf(Definition::class, $delay);
        $factory = $delay->getFactory();
        static::assertIsArray($factory);
        static::assertSame(StagingDelay::class, $factory[0]);
        static::assertSame('interval', $factory[1]);
        static::assertSame([null, 120], $delay->getArguments());
    }

    #[Test]
    public function aConfiguredStagingDelayReachesTheRotator(): void
    {
        // When
        $container = self::load([
            'keys' => [
                'kms' => 'op',
                'key_id' => 'k',
                'jwks_max_age' => 120,
                'staging_delay' => 30,
            ],
        ]);

        // Then
        $delay = $container->getDefinition(TenantKeyRotator::class)->getArgument('$stagingDelay');
        static::assertInstanceOf(Definition::class, $delay);
        static::assertSame([30, 120], $delay->getArguments());
    }

    /**
     * Decision 0009: what a tenant does with a client that registers itself reaches the bridge that
     * answers for that tenant, the mode it names and the two durations it keeps a client for.
     */
    #[Test]
    public function theRegistrationPolicyOfTheConfigurationReachesTheBridge(): void
    {
        // When
        $container = self::load([
            'client_registration' => [
                'mode' => OpenRegistrationAuthorization::MODE,
                'exempt_confidential_clients_from_pkce' => true,
                'keep_a_client_unused_for' => 86400,
                'keep_a_client_never_used_for' => 3600,
            ],
        ]);

        // Then
        $policies = $container->getDefinition(ConfigurationClientRegistrationPolicy::class);
        static::assertSame(OpenRegistrationAuthorization::MODE, $policies->getArgument('$mode'));
        static::assertTrue($policies->getArgument('$exemptsConfidentialClientsFromPkce'));
        static::assertSame('PT86400S', self::interval($container, ConfigurationClientRegistrationPolicy::class, '$keepsAClientUnusedFor'));
        static::assertSame('PT3600S', self::interval($container, ConfigurationClientRegistrationPolicy::class, '$keepsAClientNeverUsedFor'));
    }

    /**
     * Decision 0009: closed is the default, and the mode is a value of one tenant's policy: there is no
     * key here, whatever its name, that opens a registration endpoint for a deployment. What a deployment
     * that writes nothing hands the bridge is no mode at all, which is no policy and no endpoint.
     */
    #[Test]
    public function aDeploymentThatWritesNothingHandsTheBridgeNoMode(): void
    {
        // When
        $container = self::load([]);

        // Then
        static::assertNull($container->getDefinition(ConfigurationClientRegistrationPolicy::class)->getArgument('$mode'));
    }

    #[Test]
    public function theClientsReachTheConfigurationRepository(): void
    {
        // When
        $container = self::load([
            'clients' => [
                'app' => [
                    'redirect_uris' => ['https://app.test/cb'],
                    'token_endpoint_auth_method' => 'none',
                ],
            ],
        ]);

        // Then
        $clients = $container->getDefinition(ConfigurationClientRepository::class)->getArgument('$definitions');
        static::assertIsArray($clients);
        static::assertSame(['app'], array_keys($clients));
    }

    /**
     * Architecture §4.6: the shape is a per-client option. The tree reads the name and nothing else; a
     * client that names none leaves it to the wiring, which is what knows the shapes and their order.
     */
    #[Test]
    public function theAccessTokenShapeOfAClientIsRead(): void
    {
        // When
        $container = self::load([
            'clients' => [
                'app' => [
                    'redirect_uris' => ['https://app.test/cb'],
                    'token_endpoint_auth_method' => 'none',
                ],
                'api-app' => [
                    'redirect_uris' => ['https://api.test/cb'],
                    'token_endpoint_auth_method' => 'none',
                    'access_token_format' => 'opaque',
                ],
            ],
        ]);

        // Then
        $clients = $container->getDefinition(ConfigurationClientRepository::class)->getArgument('$definitions');
        static::assertIsArray($clients);
        static::assertIsArray($clients['app']);
        static::assertIsArray($clients['api-app']);
        static::assertNull($clients['app']['access_token_format']);
        static::assertSame('opaque', $clients['api-app']['access_token_format']);
    }

    /**
     * Architecture §4.6: one class per shape, tagged, and the shape it writes is the issuer's own
     * business; the wiring holds an order and no name (issue #239).
     */
    #[Test]
    public function theAccessTokenIssuersAreTaggedAndNothingNamesTheirShape(): void
    {
        // When
        $container = self::load([]);

        // Then
        foreach ([JwtAccessTokenIssuer::class, OpaqueAccessTokenIssuer::class] as $issuer) {
            static::assertArrayHasKey('beffroi.oidc.access_token_issuer', $container->getDefinition($issuer)->getTags());
        }
        foreach ([JwtAccessTokenVerifier::class, OpaqueAccessTokenVerifier::class] as $verifier) {
            static::assertArrayHasKey('beffroi.oidc.access_token_verifier', $container->getDefinition($verifier)->getTags());
        }
    }

    /**
     * Architecture §5.2: a process serves both planes unless BEFFROI_PLANE says otherwise.
     */
    #[Test]
    public function theDefaultPlaneIsBoth(): void
    {
        // When
        $container = self::load([]);

        // Then
        static::assertSame('all', $container->getParameterBag()->all()['env(BEFFROI_PLANE)']);
    }

    /**
     * The application may set the default plane of its processes itself; the bundle does not override it.
     */
    #[Test]
    public function theApplicationKeepsItsOwnDefaultPlane(): void
    {
        // Given
        $container = new ContainerBuilder();
        $container->setParameter('env(BEFFROI_PLANE)', 'protocol');

        // When
        self::load([], $container);

        // Then
        static::assertSame('protocol', $container->getParameterBag()->all()['env(BEFFROI_PLANE)']);
    }

    /**
     * Decisions 0011 and 0018: what registers the encrypted types runs while the bundles boot, and what it
     * is handed is the encrypter of the sealed columns, so an encrypter built there would build the store,
     * the connection and the KMS client of every process that boots. It is lazy, and public because a
     * private service with one consumer is inlined and an inlined service is not a proxy.
     */
    #[Test]
    public function theEncrypterOfTheSealedColumnsIsLazySoThatABootReachesNoKms(): void
    {
        // When
        $container = self::load([]);

        // Then
        $encrypter = $container->getDefinition('beffroi.personal_data.encrypter');
        static::assertTrue($encrypter->isLazy());
        static::assertTrue($encrypter->isPublic());
    }

    /**
     * @param array<string, mixed> $config
     */
    private static function load(array $config, ?ContainerBuilder $container = null): ContainerBuilder
    {
        $container ??= new ContainerBuilder();
        $extension = new BeffroiBundle()->getContainerExtension();
        static::assertNotNull($extension);
        $extension->load([
            $config
                + [
                    'tenant' => [
                        'issuer' => 'https://op.test',
                    ],
                    'keys' => [
                        'kms' => 'op',
                        'key_id' => 'signing',
                    ],
                ],
        ], $container);

        return $container;
    }

    private static function interval(ContainerBuilder $container, string $service, string $argument): string
    {
        $definition = $container->getDefinition($service)->getArgument($argument);
        static::assertInstanceOf(Definition::class, $definition);
        static::assertSame(DateInterval::class, $definition->getClass());
        $spec = $definition->getArgument(0);
        static::assertIsString($spec);

        return $spec;
    }
}
