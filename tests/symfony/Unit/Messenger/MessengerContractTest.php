<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Messenger;

use function array_count_values;
use function array_keys;
use function array_unique;
use function array_values;
use Beffroi\Bundle\BeffroiBundle;
use Beffroi\Bundle\Message\Command;
use Beffroi\Bundle\Message\Event;
use Beffroi\Bundle\Message\Notification;
use Beffroi\Bundle\Message\Query;
use Beffroi\Bundle\Message\SyncMessage;
use Beffroi\Bundle\Messenger\MessengerContract;
use Beffroi\Core\Domain\Event\DomainEventInterface;
use Symfony\Component\Messenger\MessengerBundle;
use function count;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\ExtensionInterface;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;

/**
 * Issue #456: the buses, their middleware and where each marker is sent are the contract of this provider,
 * so the bundle says them and an application is left with its transports.
 */
final class MessengerContractTest extends TestCase
{
    /**
     * Every marker of the bundle is routed, and the events of the core are routed by the interface they
     * all implement: a message whose marker is missing here leaves through no transport at all.
     */
    #[Test]
    public function everyMarkerIsRouted(): void
    {
        // When
        $routed = array_keys(MessengerContract::routing());

        // Then
        foreach ([Command::class, Event::class, Notification::class, Query::class, SyncMessage::class, DomainEventInterface::class] as $marker) {
            static::assertContains($marker, $routed);
        }
        static::assertCount(6, $routed);
    }

    /**
     * One marker, one transport: Messenger sends a message to every transport its class, its parents and
     * its interfaces are routed to, so a marker named twice would send a message twice.
     */
    #[Test]
    public function noMarkerIsRoutedTwice(): void
    {
        // When
        $routing = MessengerContract::routing();

        // Then
        static::assertCount(count($routing), array_unique(array_keys($routing)));
    }

    /**
     * Every transport the routing names is a transport the contract declares, or an application would have
     * to guess which lanes it owes.
     */
    #[Test]
    public function everyTransportRoutedToIsDeclared(): void
    {
        // Given
        $declared = array_keys(self::transports());

        // When
        $named = array_values(MessengerContract::routing());

        // Then
        foreach ($named as $transport) {
            static::assertContains($transport, $declared);
        }
    }

    #[Test]
    public function theLanesAreTheOnlyTransportsThatFollowTheDsnOfADeployment(): void
    {
        // Given
        $transports = self::transports();

        // When / Then
        foreach (MessengerContract::LANES as $lane) {
            $lane = $transports[$lane] ?? null;
            static::assertIsArray($lane);
            static::assertSame('%env(' . MessengerContract::DSN_ENVIRONMENT_VARIABLE . ')%', $lane['dsn'] ?? null);
        }
        static::assertSame('sync://', $transports['sync'] ?? null);
        static::assertSame(MessengerContract::FAILURE_DSN, $transports[MessengerContract::FAILURE_TRANSPORT] ?? null);
    }

    /**
     * The two the issue names, because an installation that gets either wrong breaks the asynchronous half
     * of the provider: an event announced from a handler has to leave after that handler committed, and a
     * use case has to be one unit of work.
     */
    #[Test]
    public function theCommandBusCarriesWhatMakesAUseCaseOneUnitOfWork(): void
    {
        // When / Then
        static::assertContains('dispatch_after_current_bus', MessengerContract::COMMAND_MIDDLEWARE);
        static::assertContains('doctrine_transaction', MessengerContract::COMMAND_MIDDLEWARE);
        static::assertSame('doctrine_transaction', MessengerContract::COMMAND_MIDDLEWARE[count(MessengerContract::COMMAND_MIDDLEWARE) - 1]);
    }

    /**
     * No middleware twice: the chain is the one thing nobody should have to reason about twice, and a list
     * that repeats an entry runs it twice.
     */
    #[Test]
    public function noMiddlewareIsListedTwice(): void
    {
        // When
        $counts = array_count_values(MessengerContract::COMMAND_MIDDLEWARE);

        // Then
        foreach ($counts as $middleware => $times) {
            static::assertSame(1, $times, (string) $middleware);
        }
    }

    /**
     * It needs symfony/validator, which this bundle does not require, and the messages of this provider
     * carry no constraint for it to check.
     */
    #[Test]
    public function theCommandBusDoesNotCarryValidation(): void
    {
        // When / Then
        static::assertNotContains('validation', MessengerContract::COMMAND_MIDDLEWARE);
    }

    /**
     * The bundle prepends the block, and defaults the one environment variable it reads, so that an
     * installation that says nothing at all gets the database.
     */
    #[Test]
    public function theBundlePrependsTheContractAndDefaultsTheDsnToTheDatabase(): void
    {
        // Given
        $builder = new ContainerBuilder();
        $builder->registerExtension(self::messengerExtension());

        // When
        new BeffroiBundle()->prependExtension(self::configurator($builder), $builder);

        // Then
        static::assertSame(
            [MessengerContract::configuration()],
            $builder->getExtensionConfig('messenger'),
        );
        static::assertSame(MessengerContract::DEFAULT_DSN, self::rawParameter($builder));
    }

    /**
     * A deployment that named the lane itself keeps it: the bundle defaults the variable and never
     * overwrites it.
     */
    #[Test]
    public function aDeploymentThatNamedTheDsnKeepsIt(): void
    {
        // Given
        $builder = new ContainerBuilder();
        $builder->registerExtension(self::messengerExtension());
        $builder->setParameter('env(' . MessengerContract::DSN_ENVIRONMENT_VARIABLE . ')', 'amqp://rabbit');

        // When
        new BeffroiBundle()->prependExtension(self::configurator($builder), $builder);

        // Then
        static::assertSame('amqp://rabbit', self::rawParameter($builder));
    }

    /**
     * An installation without the component gets nothing prepended rather than a configuration no
     * extension reads.
     */
    #[Test]
    public function anInstallationWithoutTheComponentGetsNothing(): void
    {
        // Given
        $builder = new ContainerBuilder();

        // When
        new BeffroiBundle()->prependExtension(self::configurator($builder), $builder);

        // Then
        static::assertFalse($builder->hasParameter('env(' . MessengerContract::DSN_ENVIRONMENT_VARIABLE . ')'));
    }

    /**
     * The value as the bag holds it: reading an "env()" parameter back gives the placeholder that stands
     * for it until the container is compiled, which says nothing about what was defaulted.
     */
    private static function rawParameter(ContainerBuilder $builder): string
    {
        $value = $builder->getParameterBag()->all()['env(' . MessengerContract::DSN_ENVIRONMENT_VARIABLE . ')'] ?? null;
        static::assertIsString($value);

        return $value;
    }

    /**
     * @return array<string, mixed>
     */
    private static function transports(): array
    {
        $transports = MessengerContract::configuration()['transports'] ?? null;
        static::assertIsArray($transports);

        /** @var array<string, mixed> $transports */
        return $transports;
    }

    /**
     * The extension of the component itself, because what the bundle looks for is whether the component is
     * installed, and that is what having its extension means.
     */
    private static function messengerExtension(): ExtensionInterface
    {
        return new MessengerBundle()->getContainerExtension() ?? static::fail('The messenger component has no extension.');
    }

    private static function configurator(ContainerBuilder $builder): ContainerConfigurator
    {
        $instanceof = [];

        return new ContainerConfigurator($builder, new PhpFileLoader($builder, new FileLocator()), $instanceof, '', '');
    }
}
