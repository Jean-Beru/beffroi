<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Messenger;

use function array_count_values;
use function array_keys;
use function array_unique;
use function array_values;
use App\Configuration\SecretFile;
use App\DependencyInjection\BeffroiExtension;
use App\Message\Command;
use App\Message\Event;
use App\Message\Notification;
use App\Message\Query;
use App\Message\SyncMessage;
use App\Messenger\LaneDsn;
use App\Messenger\MessengerContract;
use Beffroi\Core\Domain\Event\DomainEventInterface;
use Symfony\Component\Messenger\MessengerBundle;
use function count;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\ExtensionInterface;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;

final class MessengerContractTest extends TestCase
{
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

    #[Test]
    public function noMarkerIsRoutedTwice(): void
    {
        // When
        $routing = MessengerContract::routing();

        // Then
        static::assertCount(count($routing), array_unique(array_keys($routing)));
    }

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
        foreach (MessengerContract::LANES as $name) {
            $lane = $transports[$name] ?? null;
            static::assertIsArray($lane);
            static::assertSame(LaneDsn::of($name, SecretFile::PREFIX . ':' . MessengerContract::DSN_ENVIRONMENT_VARIABLE), $lane['dsn'] ?? null);
        }
        static::assertSame('sync://', $transports['sync'] ?? null);
        static::assertSame(
            ['dsn' => MessengerContract::FAILURE_DSN, 'options' => MessengerContract::TRANSPORT_OPTIONS],
            $transports[MessengerContract::FAILURE_TRANSPORT] ?? null,
        );
    }

    #[Test]
    public function theCommandBusCarriesWhatMakesAUseCaseOneUnitOfWork(): void
    {
        // When / Then
        static::assertSame('doctrine_transaction', MessengerContract::COMMAND_MIDDLEWARE[count(MessengerContract::COMMAND_MIDDLEWARE) - 1]);
    }

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

    #[Test]
    #[DataProvider('provideDefaultMiddleware')]
    public function theCommandBusNamesNothingTheDefaultsAlreadyCarry(string $middleware): void
    {
        // When / Then
        static::assertNotContains($middleware, MessengerContract::COMMAND_MIDDLEWARE);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideDefaultMiddleware(): iterable
    {
        yield 'add_bus_name_stamp_middleware' => ['add_bus_name_stamp_middleware'];
        yield 'dispatch_after_current_bus' => ['dispatch_after_current_bus'];
        yield 'failed_message_processing_middleware' => ['failed_message_processing_middleware'];
        yield 'send_message' => ['send_message'];
        yield 'handle_message' => ['handle_message'];
    }

    #[Test]
    public function noBusTurnsTheDefaultMiddlewareOff(): void
    {
        // When
        $buses = self::buses();

        // Then
        $command = $buses['command.bus'];
        $event = $buses['event.bus'];
        static::assertIsArray($command);
        static::assertIsArray($event);
        static::assertNull($buses['query.bus']);
        static::assertArrayNotHasKey('default_middleware', $command);
        static::assertSame('allow_no_handlers', $event['default_middleware'] ?? null);
    }

    /**
     * @return array<string, mixed>
     */
    private static function buses(): array
    {
        $buses = MessengerContract::configuration()['buses'] ?? null;
        static::assertIsArray($buses);

        /** @var array<string, mixed> $buses */
        return $buses;
    }

    #[Test]
    public function theCommandBusDoesNotCarryValidation(): void
    {
        // When / Then
        static::assertNotContains('validation', MessengerContract::COMMAND_MIDDLEWARE);
    }

    #[Test]
    public function theProviderPrependsTheContractAndDefaultsTheDsnToTheDatabase(): void
    {
        // Given
        $builder = new ContainerBuilder();
        $builder->registerExtension(self::messengerExtension());

        // When
        new BeffroiExtension()->prependExtension(self::configurator($builder), $builder);

        // Then
        static::assertSame(
            [MessengerContract::configuration()],
            $builder->getExtensionConfig('messenger'),
        );
        static::assertSame(MessengerContract::DEFAULT_DSN, self::rawParameter($builder));
    }

    #[Test]
    public function aDeploymentThatNamedTheDsnKeepsIt(): void
    {
        // Given
        $builder = new ContainerBuilder();
        $builder->registerExtension(self::messengerExtension());
        $builder->setParameter('env(' . MessengerContract::DSN_ENVIRONMENT_VARIABLE . ')', 'redis://redis');

        // When
        new BeffroiExtension()->prependExtension(self::configurator($builder), $builder);

        // Then
        static::assertSame('redis://redis', self::rawParameter($builder));
    }

    #[Test]
    public function anInstallationWithoutTheComponentGetsNothing(): void
    {
        // Given
        $builder = new ContainerBuilder();

        // When
        new BeffroiExtension()->prependExtension(self::configurator($builder), $builder);

        // Then
        static::assertFalse($builder->hasParameter('env(' . MessengerContract::DSN_ENVIRONMENT_VARIABLE . ')'));
    }

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
