<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Saml;

use App\DependencyInjection\BeffroiExtension;
use App\Saml\MappedClaimsWarmer;
use App\Saml\ServiceProvidersPass;
use Beffroi\Saml\Bridge\Configuration\ConfigurationServiceProviders;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * spec/saml.md section 6.2 step 1
 */
final class ServiceProvidersPassTest extends TestCase
{
    private const string ENTITY_ID = 'https://sp.example.com/saml';

    /**
     * Section 6.2 step 1
     *
     * @param array<array-key, mixed> $declaration
     */
    #[Test]
    #[DataProvider('provideDeclarationsThatDoNotHoldTogether')]
    public function aDeclarationThatDoesNotHoldTogetherFailsTheCompilation(string $entityId, array $declaration, string $message): void
    {
        // Given
        $container = self::container([
            $entityId => $declaration,
        ]);

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs(\sprintf(
            'Invalid configuration for path "beffroi.saml.service_providers": The service provider "%s": %s',
            $entityId,
            $message,
        ));

        // When
        new ServiceProvidersPass()->process($container);
    }

    /**
     * @return iterable<string, array{string, array<array-key, mixed>, string}>
     */
    public static function provideDeclarationsThatDoNotHoldTogether(): iterable
    {
        yield 'a plain http location' => [
            self::ENTITY_ID,
            ['metadata' => 'http://sp.example.com/saml/metadata'],
            'The metadata of a service provider or of an identity provider are read from an https URL or from the absolute path of a file (spec/saml.md S-5, S-42).',
        ];
        yield 'an entity ID that holds whitespace' => [
            'https://sp.example.com/my saml',
            ['metadata' => 'https://sp.example.com/saml/metadata'],
            'The entity ID of a service provider is not empty, holds no whitespace and is at most 1024 characters (spec/saml.md section 6.2 step 1).',
        ];
        yield 'a signer that is no certificate' => [
            self::ENTITY_ID,
            ['metadata' => 'https://sp.example.com/saml/metadata', 'metadata_signers' => ['not a certificate']],
            'A certificate is the base64 of its DER, in the alphabet of RFC 4648 section 4 (spec/saml.md section 5.1).',
        ];
        yield 'an attribute of the uri format whose name is no URI' => [
            self::ENTITY_ID,
            ['metadata' => 'https://sp.example.com/saml/metadata', 'attributes' => ['mail' => ['claim' => 'email']]],
            'An attribute name of the uri format is an absolute URI (Core section 8.2.2, spec/saml.md section 6.2 step 1).',
        ];
    }

    /**
     * Section 6.2 step 1
     */
    #[Test]
    public function aDeclarationThatHoldsTogetherCompiles(): void
    {
        // Given
        $container = self::container([
            self::ENTITY_ID => [
                'metadata' => '/srv/saml/sp-metadata.xml',
                'attributes' => [
                    'urn:oid:0.9.2342.19200300.100.1.3' => [
                        'claim' => 'email',
                    ],
                ],
            ],
        ]);
        $written = self::declarations($container);

        // When
        new ServiceProvidersPass()->process($container);

        // Then
        static::assertSame($written, self::declarations($container));
    }

    /**
     * S-16, section 6.2 step 1
     */
    #[Test]
    public function theClaimOfAMappingIsLeftToTheWarmer(): void
    {
        // Given
        $container = self::container([
            self::ENTITY_ID => [
                'metadata' => '/srv/saml/sp-metadata.xml',
                'attributes' => [
                    'urn:oid:1.3.6.1.4.1.5923.1.1.1.6' => [
                        'claim' => 'a_claim_no_provider_serves',
                    ],
                ],
            ],
        ]);
        $written = self::declarations($container);

        // When
        new ServiceProvidersPass()->process($container);

        // Then
        static::assertSame($written, self::warmed($container));
    }

    /**
     * Section 6.2 step 1
     */
    #[Test]
    public function aDeclarationThatHoldsAnEnvironmentVariableIsLeftToItsFirstUse(): void
    {
        // Given
        $container = new ContainerBuilder();
        $location = $container->getParameterBag()->get('env(SP_METADATA)');
        $container = self::container([
            self::ENTITY_ID => [
                'metadata' => $location,
            ],
        ], $container);

        // When
        new ServiceProvidersPass()->process($container);

        // Then
        static::assertSame($location, self::declarations($container)[self::ENTITY_ID]['metadata'] ?? null);
    }

    /**
     * Section 6.2 step 1
     */
    #[Test]
    public function aDeclarationThatHoldsAnEnvironmentVariableIsNotHandedToTheWarmer(): void
    {
        // Given
        $container = new ContainerBuilder();
        $container = self::container([
            'https://env.example.com/saml' => [
                'metadata' => $container->getParameterBag()->get('env(SP_METADATA)'),
            ],
            self::ENTITY_ID => [
                'metadata' => '/srv/saml/sp-metadata.xml',
            ],
        ], $container);

        // When
        new ServiceProvidersPass()->process($container);

        // Then
        static::assertSame([self::ENTITY_ID], \array_keys(self::warmed($container)));
    }

    #[Test]
    public function aDeclarationThatDoesNotHoldTogetherBesideOneOfTheEnvironmentFails(): void
    {
        // Given
        $container = new ContainerBuilder();
        $container = self::container([
            'https://env.example.com/saml' => [
                'metadata' => $container->getParameterBag()->get('env(SP_METADATA)'),
            ],
            self::ENTITY_ID => [
                'metadata' => 'http://sp.example.com/saml/metadata',
            ],
        ], $container);

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIsOrContains('The service provider "https://sp.example.com/saml": The metadata of a service provider or of an identity provider are read from an https URL');

        // When
        new ServiceProvidersPass()->process($container);
    }

    #[Test]
    public function aContainerWithoutTheServiceProvidersHasNothingToCheck(): void
    {
        // Given
        $container = new ContainerBuilder();

        // When
        new ServiceProvidersPass()->process($container);

        // Then
        static::assertFalse($container->hasDefinition(ConfigurationServiceProviders::class));
    }

    #[Test]
    public function theProviderRunsThePass(): void
    {
        // Given
        $container = new ContainerBuilder();

        // When
        BeffroiExtension::addCompilerPasses($container);

        // Then
        $passes = \array_filter(
            $container->getCompilerPassConfig()->getBeforeOptimizationPasses(),
            static fn (object $pass): bool => $pass instanceof ServiceProvidersPass,
        );
        static::assertCount(1, $passes);
    }

    /**
     * @param array<array-key, mixed> $serviceProviders
     */
    private static function container(array $serviceProviders, ?ContainerBuilder $container = null): ContainerBuilder
    {
        $container ??= new ContainerBuilder();
        $extension = new BeffroiExtension();
        $extension->load([
            [
                'tenant' => [
                    'issuer' => 'https://op.test',
                ],
                'keys' => [
                    'kms' => 'op',
                    'key_id' => 'signing',
                ],
                'saml' => [
                    'identity_provider' => null,
                    'service_providers' => $serviceProviders,
                ],
            ],
        ], $container);

        return $container;
    }

    /**
     * @return array<array-key, array<array-key, mixed>>
     */
    private static function declarations(ContainerBuilder $container): array
    {
        $declarations = $container->getDefinition(ConfigurationServiceProviders::class)->getArgument('$definitions');
        static::assertIsArray($declarations);

        /** @var array<array-key, array<array-key, mixed>> $declarations */
        return $declarations;
    }

    /**
     * @return array<array-key, mixed>
     */
    private static function warmed(ContainerBuilder $container): array
    {
        $declarations = $container->getDefinition(MappedClaimsWarmer::class)->getArgument('$declarations');
        static::assertIsArray($declarations);

        return $declarations;
    }
}
