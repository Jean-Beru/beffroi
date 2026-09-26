<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit;

use DateInterval;
use Heidi\Bundle\HeidiBundle;
use Heidi\Bundle\Key\FileTenantKeyRepository;
use Heidi\Bundle\Key\StagingDelay;
use Heidi\Bundle\Tenant\TenantFactory;
use Heidi\Core\Application\Key\TenantKeyRotator;
use Heidi\Core\Bridge\KeyManagement\EnvelopeKeySealer;
use Heidi\Oidc\Application\Authorization\AuthorizationCodeIssuer;
use Heidi\Oidc\Application\Token\AuthorizationCodeGrant;
use Heidi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Heidi\Oidc\Application\Token\JwtAccessTokenVerifier;
use Heidi\Oidc\Application\Token\JwtIdTokenIssuer;
use Heidi\Oidc\Application\Token\OpaqueAccessTokenIssuer;
use Heidi\Oidc\Application\Token\OpaqueAccessTokenVerifier;
use Heidi\Oidc\Application\Token\TokenIssuer;
use Heidi\Oidc\Bridge\Configuration\ConfigurationClientRepository;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;

/**
 * What the extension hands the services from the configuration, read on the definitions before the
 * container is compiled: the values of "heidi.tokens" become the DateIntervals of the use cases, the
 * values of "heidi.keys" and "heidi.tenant" the arguments of the bridges.
 */
final class HeidiBundleExtensionTest extends TestCase
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
                'storage' => '/var/lib/heidi/keys',
            ],
        ]);

        // Then
        $factory = $container->getDefinition(TenantFactory::class);
        static::assertSame('https://op.test/tenant-a', $factory->getArgument('$issuer'));
        static::assertSame('tenant-a', $factory->getArgument('$slug'));
        static::assertSame('Tenant A', $factory->getArgument('$name'));
        static::assertSame('key_management.op', (string) $container->getAlias('heidi.kms'));
        static::assertSame('k', $container->getDefinition(EnvelopeKeySealer::class)->getArgument('$kmsKeyId'));
        static::assertSame('/var/lib/heidi/keys', $container->getDefinition(FileTenantKeyRepository::class)->getArgument('$directory'));
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
            static::assertArrayHasKey('heidi.oidc.access_token_issuer', $container->getDefinition($issuer)->getTags());
        }
        foreach ([JwtAccessTokenVerifier::class, OpaqueAccessTokenVerifier::class] as $verifier) {
            static::assertArrayHasKey('heidi.oidc.access_token_verifier', $container->getDefinition($verifier)->getTags());
        }
    }

    /**
     * Architecture §5.2: a process serves both planes unless HEIDI_PLANE says otherwise.
     */
    #[Test]
    public function theDefaultPlaneIsBoth(): void
    {
        // When
        $container = self::load([]);

        // Then
        static::assertSame('all', $container->getParameterBag()->all()['env(HEIDI_PLANE)']);
    }

    /**
     * The application may set the default plane of its processes itself; the bundle does not override it.
     */
    #[Test]
    public function theApplicationKeepsItsOwnDefaultPlane(): void
    {
        // Given
        $container = new ContainerBuilder();
        $container->setParameter('env(HEIDI_PLANE)', 'protocol');

        // When
        self::load([], $container);

        // Then
        static::assertSame('protocol', $container->getParameterBag()->all()['env(HEIDI_PLANE)']);
    }

    /**
     * @param array<string, mixed> $config
     */
    private static function load(array $config, ?ContainerBuilder $container = null): ContainerBuilder
    {
        $container ??= new ContainerBuilder();
        $extension = new HeidiBundle()->getContainerExtension();
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
