<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Saml;

use App\DependencyInjection\BeffroiExtension;
use App\Saml\RouterServiceProviderEndpoints;
use App\Saml\ServiceProviderEntityIdPass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * spec/saml.md S-38, M-6
 */
final class ServiceProviderEntityIdPassTest extends TestCase
{
    private const string ISSUER = 'https://op.test';

    /**
     * S-38, M-6
     *
     * @param array<string, mixed> $saml
     */
    #[Test]
    #[DataProvider('provideEntityIdsRefused')]
    public function anEntityIdThatBreaksARuleFailsTheCompilation(array $saml, string $message): void
    {
        // Given
        $container = self::container($saml);

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('Invalid configuration for path "beffroi.saml.service_provider.entity_id": ' . $message);

        // When
        new ServiceProviderEntityIdPass()->process($container);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideEntityIdsRefused(): iterable
    {
        $identityProvider = 'The entity ID of the service provider of the tenant, "https://op.test/saml/metadata", is the one of its identity provider: each role is an entity of its own (spec/saml.md S-38).';
        yield 'the entity ID of the identity provider, enabled' => [
            [
                'identity_provider' => null,
                'service_provider' => [
                    'entity_id' => self::ISSUER . '/saml/metadata',
                ],
            ],
            $identityProvider,
        ];
        yield 'the entity ID of the identity provider, left off' => [
            [
                'service_provider' => [
                    'entity_id' => self::ISSUER . '/saml/metadata',
                ],
            ],
            $identityProvider,
        ];
        yield 'no scheme' => [
            [
                'service_provider' => [
                    'entity_id' => 'sp.example',
                ],
            ],
            'The entity ID of the service provider of a tenant is refused (spec/saml.md S-38): A URI is not absolute (M-6).',
        ];
        yield 'a format character' => [
            [
                'service_provider' => [
                    'entity_id' => "https://op.test/saml\u{200B}sp",
                ],
            ],
            'The entity ID of the service provider of a tenant is refused (spec/saml.md S-38): A URI holds whitespace, a control, format or invisible character, or bytes that are not UTF-8 (M-6).',
        ];
    }

    /**
     * S-38
     */
    #[Test]
    public function anEntityIdOfItsOwnCompiles(): void
    {
        // Given
        $container = self::container([
            'service_provider' => [
                'entity_id' => 'urn:example:op:service-provider',
            ],
        ]);

        // When
        new ServiceProviderEntityIdPass()->process($container);

        // Then
        static::assertSame('urn:example:op:service-provider', self::locatorEntityId($container));
    }

    /**
     * S-38
     */
    #[Test]
    public function anEntityIdOfTheEnvironmentIsLeftToTheLocator(): void
    {
        // Given
        $container = new ContainerBuilder();
        $entityId = $container->getParameterBag()->get('env(SP_ENTITY_ID)');
        $container = self::container([
            'service_provider' => [
                'entity_id' => $entityId,
            ],
        ], $container);

        // When
        new ServiceProviderEntityIdPass()->process($container);

        // Then
        static::assertSame($entityId, self::locatorEntityId($container));
    }

    /**
     * S-38
     */
    #[Test]
    public function anIssuerOfTheEnvironmentLeavesTheComparisonToTheLocator(): void
    {
        // Given
        $container = new ContainerBuilder();
        $issuer = $container->getParameterBag()->get('env(ISSUER)');
        static::assertIsString($issuer);
        $container = self::container(
            [
                'service_provider' => [
                    'entity_id' => self::ISSUER . '/saml/metadata',
                ],
            ],
            $container,
            $issuer,
        );

        // When
        new ServiceProviderEntityIdPass()->process($container);

        // Then
        static::assertSame(self::ISSUER . '/saml/metadata', self::locatorEntityId($container));
    }

    /**
     * S-38
     */
    #[Test]
    public function anEntityIdLeftOutCompiles(): void
    {
        // Given
        $container = self::container([
            'service_provider' => null,
        ]);

        // When
        new ServiceProviderEntityIdPass()->process($container);

        // Then
        static::assertNull(self::locatorEntityId($container));
    }

    /**
     * S-38, Decision 0030
     */
    #[Test]
    public function anEntityIdOfAServiceProviderLeftOffIsHeldToItsRules(): void
    {
        // Given
        $container = self::container([
            'service_provider' => [
                'enabled' => false,
                'entity_id' => 'sp.example',
            ],
        ]);

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('Invalid configuration for path "beffroi.saml.service_provider.entity_id": The entity ID of the service provider of a tenant is refused (spec/saml.md S-38): A URI is not absolute (M-6).');

        // When
        new ServiceProviderEntityIdPass()->process($container);
    }

    #[Test]
    public function theProviderRunsThePass(): void
    {
        // Given
        $container = new ContainerBuilder();

        // When
        BeffroiExtension::addCompilerPasses($container);

        // Then
        static::assertCount(1, \array_filter(
            $container->getCompilerPassConfig()->getBeforeOptimizationPasses(),
            static fn (object $pass): bool => $pass instanceof ServiceProviderEntityIdPass,
        ));
    }

    /**
     * @param array<string, mixed> $saml
     */
    private static function container(array $saml, ?ContainerBuilder $container = null, string $issuer = self::ISSUER): ContainerBuilder
    {
        $container ??= new ContainerBuilder();
        $extension = new BeffroiExtension();
        $extension->load([
            [
                'tenant' => [
                    'issuer' => $issuer,
                ],
                'keys' => [
                    'kms' => 'op',
                    'key_id' => 'signing',
                ],
                'saml' => $saml,
            ],
        ], $container);

        return $container;
    }

    private static function locatorEntityId(ContainerBuilder $container): mixed
    {
        return $container->getDefinition(RouterServiceProviderEndpoints::class)->getArgument('$entityId');
    }
}
