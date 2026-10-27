<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Configuration;

use Beffroi\Bundle\Configuration\EnvironmentListDefinition;
use Beffroi\Bundle\Configuration\EnvironmentListNode;
use function is_string;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;

/**
 * Decision 0030: a list of the configuration an environment variable may carry whole, declared as an array node is,
 * and normalized by the same tree when the variable is a value.
 */
final class EnvironmentListDefinitionTest extends TestCase
{
    #[Test]
    public function itBuildsAListTheEnvironmentMayCarry(): void
    {
        // When / Then
        static::assertInstanceOf(EnvironmentListNode::class, self::issuers()->getNode(true));
    }

    /**
     * The list stays the node Symfony builds: an environment variable, which an array node of symfony/config 8.2
     * refuses, stands for it whole in a container compiled with it, whatever the type its processor gives it, and the
     * container reads the list the variable carries.
     */
    #[Test]
    #[DataProvider('provideVariables')]
    public function aContainerIsCompiledWithAVariableForTheWholeList(string $variable, mixed $list): void
    {
        // Given
        $container = new ContainerBuilder();
        $container->setParameter('env(BEFFROI_TEST_ISSUERS)', '{"https://issuer.example":{"clients":["app"]}}');
        $container->registerExtension(self::extension());
        $container->loadFromExtension('list_fixture', ['issuers' => $variable]);

        // When
        $container->compile(true);

        // Then
        static::assertSame($list, $container->getParameter('list_fixture.issuers'));
    }

    /**
     * @return iterable<string, array{string, mixed}>
     */
    public static function provideVariables(): iterable
    {
        yield 'a JSON document' => ['%env(json:BEFFROI_TEST_ISSUERS)%', ['https://issuer.example' => ['clients' => ['app']]]];
        yield 'a string' => ['%env(BEFFROI_TEST_ISSUERS)%', '{"https://issuer.example":{"clients":["app"]}}'];
    }

    /**
     * What the environment carries is normalized as a written list is, the defaults of its entries filled in.
     */
    #[Test]
    public function aListOfTheEnvironmentHasTheDefaultsOfAWrittenOne(): void
    {
        // When
        $list = self::issuers()->normalized(['https://issuer.example' => ['clients' => ['app']]], 'trusted_issuers');

        // Then
        static::assertSame(['https://issuer.example' => ['clients' => ['app'], 'jwks' => null]], $list);
    }

    #[Test]
    public function aListOfTheEnvironmentIsRefusedWhatAWrittenOneIsRefused(): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIsOrContains('The "beffroi" configuration key "trusted_issuers" carried by the environment is refused: Unrecognized option "insecure" under "trusted_issuers.https://issuer.example".');

        // When
        self::issuers()->normalized(['https://issuer.example' => ['clients' => ['app'], 'insecure' => true]], 'trusted_issuers');
    }

    /**
     * A list that wraps a string, the secrets that bind the data keys, takes one entry from the environment as the
     * list of that entry.
     */
    #[Test]
    public function aListThatWrapsAStringIsTheListOfThatOneString(): void
    {
        // Given
        $secrets = new EnvironmentListDefinition('data_key_secrets');
        $secrets->wrapsAString()->scalarPrototype()->end();

        // When / Then
        static::assertSame(['a-secret'], $secrets->normalized('a-secret', 'keys.data_key_secrets'));
    }

    /**
     * An extension whose configuration is the list of issuers below, which it hands the container as a parameter.
     */
    private static function extension(): Extension
    {
        return new class extends Extension implements ConfigurationInterface {
            public function getAlias(): string
            {
                return 'list_fixture';
            }

            public function getConfigTreeBuilder(): TreeBuilder
            {
                $tree = new TreeBuilder('list_fixture');
                $tree->getRootNode()->children()->append(EnvironmentListDefinitionTest::issuers('issuers'))->end();

                return $tree;
            }

            /**
             * @param array<array-key, mixed> $config
             */
            public function getConfiguration(array $config, ContainerBuilder $container): ConfigurationInterface
            {
                return $this;
            }

            /**
             * @param array<array-key, mixed> $configs
             */
            public function load(array $configs, ContainerBuilder $container): void
            {
                // the placeholder the list is, a string until the container runs
                $issuers = $this->processConfiguration($this, $configs)['issuers'] ?? null;
                $container->setParameter('list_fixture.issuers', is_string($issuers) ? $issuers : null);
            }
        };
    }

    public static function issuers(string $name = 'trusted_issuers'): EnvironmentListDefinition
    {
        $issuers = new EnvironmentListDefinition($name);
        $issuers
            ->useAttributeAsKey('issuer')
            ->normalizeKeys(false)
            ->arrayPrototype()
            ->children()
            ->variableNode('jwks')
            ->defaultNull()
            ->end()
            ->arrayNode('clients')
            ->scalarPrototype()
            ->end()
            ->end()
            ->end()
            ->end();

        return $issuers;
    }
}
