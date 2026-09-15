<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit;

use DateInterval;
use Heidi\Bundle\HeidiBundle;
use Heidi\Bundle\Key\FileSigningKeyRepository;
use Heidi\Bundle\Tenant\TenantFactory;
use Heidi\Core\Bridge\KeyManagement\EnvelopeKeySealer;
use Heidi\Oidc\Application\Authorization\AuthorizationHandler;
use Heidi\Oidc\Application\Token\AuthorizationCodeGrant;
use Heidi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Heidi\Oidc\Application\Token\JwtIdTokenIssuer;
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
        $container = self::load([
            'tokens' => [
                'authorization_code_ttl' => 45,
                'access_token_ttl' => 300,
                'id_token_ttl' => 120,
                'refresh_token_ttl' => 1000,
                'refresh_token_absolute_ttl' => 2000,
            ],
        ]);

        static::assertSame('PT45S', self::interval($container, AuthorizationHandler::class, '$codeLifetime'));
        static::assertSame('PT300S', self::interval($container, JwtAccessTokenIssuer::class, '$lifetime'));
        static::assertSame('PT120S', self::interval($container, JwtIdTokenIssuer::class, '$lifetime'));
        static::assertSame('PT1000S', self::interval($container, TokenIssuer::class, '$refreshTokenLifetime'));
        static::assertSame('PT2000S', self::interval($container, AuthorizationCodeGrant::class, '$refreshTokenFamilyLifetime'));
    }

    #[Test]
    public function theTenantTheKeysAndTheClientsReachTheBridges(): void
    {
        $container = self::load([
            'tenant' => [
                'issuer' => 'https://op.test/tenant-a',
                'slug' => 'tenant-a',
                'name' => 'Tenant A',
            ],
            'keys' => [
                'kms' => 'sodium://?keys[k]=AAAA',
                'key_id' => 'k',
                'storage' => '/var/lib/heidi/keys',
            ],
            'clients' => [
                'app' => [
                    'redirect_uris' => ['https://app.test/cb'],
                    'token_endpoint_auth_method' => 'none',
                ],
            ],
        ]);

        $factory = $container->getDefinition(TenantFactory::class);
        static::assertSame('https://op.test/tenant-a', $factory->getArgument('$issuer'));
        static::assertSame('tenant-a', $factory->getArgument('$slug'));
        static::assertSame('Tenant A', $factory->getArgument('$name'));
        static::assertSame('sodium://?keys[k]=AAAA', $container->getDefinition('heidi.kms')->getArgument(0));
        static::assertSame('k', $container->getDefinition(EnvelopeKeySealer::class)->getArgument('$kmsKeyId'));
        static::assertSame('/var/lib/heidi/keys', $container->getDefinition(FileSigningKeyRepository::class)->getArgument('$directory'));
        $clients = $container->getDefinition(ConfigurationClientRepository::class)->getArgument('$definitions');
        static::assertIsArray($clients);
        static::assertSame(['app'], array_keys($clients));
        static::assertSame('all', $container->getParameterBag()->all()['env(HEIDI_PLANE)']);
    }

    /**
     * The application may set the default plane of its processes itself; the bundle does not override it.
     */
    #[Test]
    public function theApplicationKeepsItsOwnDefaultPlane(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('env(HEIDI_PLANE)', 'protocol');

        self::load([], $container);

        static::assertSame('protocol', $container->getParameterBag()->all()['env(HEIDI_PLANE)']);
    }

    /**
     * @param array<string, mixed> $config
     */
    private static function load(array $config, ?ContainerBuilder $container = null): ContainerBuilder
    {
        $container ??= new ContainerBuilder();
        $extension = new HeidiBundle()
            ->getContainerExtension();
        static::assertNotNull($extension);
        $extension->load([$config + [
            'tenant' => [
                'issuer' => 'https://op.test',
            ],
            'keys' => [
                'kms' => 'sodium://?keys[signing]=AAAA',
                'key_id' => 'signing',
            ],
        ]], $container);

        return $container;
    }

    private static function interval(ContainerBuilder $container, string $service, string $argument): string
    {
        $definition = $container->getDefinition($service)
            ->getArgument($argument);
        static::assertInstanceOf(Definition::class, $definition);
        static::assertSame(DateInterval::class, $definition->getClass());
        $spec = $definition->getArgument(0);
        static::assertIsString($spec);

        return $spec;
    }
}
