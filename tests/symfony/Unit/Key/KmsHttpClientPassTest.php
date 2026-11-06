<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Key;

use function array_filter;
use App\DependencyInjection\BeffroiExtension;
use App\Key\KmsHttpClientPass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\KeyManagement\Bridge\HashiCorpVault\TransitKmsFactory;
use Symfony\Component\KeyManagement\Local\SodiumKmsFactory;

final class KmsHttpClientPassTest extends TestCase
{
    #[Test]
    public function aFactoryThatTalksHttpIsHandedTheClientWhoseWaitIsBounded(): void
    {
        // Given
        $container = self::container();
        $container
            ->register('key_management.factory.hashicorp_vault_transit', TransitKmsFactory::class)
            ->setArguments([new Reference('http_client', ContainerInterface::NULL_ON_INVALID_REFERENCE)])
            ->addTag('key_management.factory');

        // When
        new KmsHttpClientPass()->process($container);

        // Then
        $argument = $container->getDefinition('key_management.factory.hashicorp_vault_transit')->getArgument(0);
        static::assertEquals(new Reference(KmsHttpClientPass::CLIENT, ContainerInterface::NULL_ON_INVALID_REFERENCE), $argument);
    }

    #[Test]
    public function theClientWaitsFiveSecondsIdleAndTenAtMost(): void
    {
        // Given
        $container = self::container();

        // When
        new KmsHttpClientPass()->process($container);

        // Then
        $client = $container->getDefinition(KmsHttpClientPass::CLIENT);
        static::assertEquals([new Reference('http_client'), 'withOptions'], $client->getFactory());
        static::assertSame([['timeout' => 5.0, 'max_duration' => 10.0]], $client->getArguments());
    }

    #[Test]
    public function aFactoryThatTalksNoHttpKeepsWhatItIsGiven(): void
    {
        // Given
        $container = self::container();
        $container
            ->register('key_management.factory.sodium', SodiumKmsFactory::class)
            ->setArguments([new Reference('key_management.key_loader')])
            ->addTag('key_management.factory');

        // When
        new KmsHttpClientPass()->process($container);

        // Then
        static::assertEquals([new Reference('key_management.key_loader')], $container->getDefinition('key_management.factory.sodium')->getArguments());
    }

    #[Test]
    public function anApplicationWithNoHttpClientIsGivenNone(): void
    {
        // Given
        $container = new ContainerBuilder();

        // When
        new KmsHttpClientPass()->process($container);

        // Then
        static::assertFalse($container->has(KmsHttpClientPass::CLIENT));
    }

    #[Test]
    public function theProviderRunsThePass(): void
    {
        // Given
        $container = new ContainerBuilder();

        // When
        BeffroiExtension::addCompilerPasses($container);

        // Then
        $passes = array_filter(
            $container->getCompilerPassConfig()->getBeforeOptimizationPasses(),
            static fn (object $pass): bool => $pass instanceof KmsHttpClientPass,
        );
        static::assertCount(1, $passes);
    }

    private static function container(): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->register('http_client', MockHttpClient::class);

        return $container;
    }
}
