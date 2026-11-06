<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Runtime;

use App\Key\KeysOpenedAtStart;
use App\Runtime\KeysOpenedFirst;
use App\Tests\Symfony\Fixture\AmbientTenant;
use App\Tests\Symfony\Fixture\CountedResets;
use App\Tests\Symfony\Fixture\RecordedMessages;
use App\Tests\Symfony\Fixture\RecordingKeys;
use Beffroi\Core\Tests\Fixture\Fixtures;
use LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use stdClass;
use Symfony\Component\DependencyInjection\Container;
use Symfony\Component\HttpKernel\KernelInterface;
use Symfony\Component\Runtime\RunnerInterface;

/**
 * Decision 0018
 */
final class KeysOpenedFirstTest extends TestCase
{
    #[Test]
    public function theThreadServesOnceItsKeysAreOpened(): void
    {
        // Given
        $keys = new RecordingKeys();
        $openedWhenItServed = null;
        $runner = static::createStub(RunnerInterface::class);
        $runner
            ->method('run')
            ->willReturnCallback(static function () use ($keys, &$openedWhenItServed): int {
                $openedWhenItServed = $keys->openedFor;

                return 0;
            });

        // When
        new KeysOpenedFirst(self::kernelHolding(self::opening($keys), new CountedResets()), $runner)->run();

        // Then
        static::assertSame(['acme'], $openedWhenItServed);
    }

    #[Test]
    public function theFirstRequestFindsTheServicesResetAsEveryLaterOne(): void
    {
        // Given
        $services = new CountedResets();
        $resetWhenItServed = null;
        $runner = static::createStub(RunnerInterface::class);
        $runner
            ->method('run')
            ->willReturnCallback(static function () use ($services, &$resetWhenItServed): int {
                $resetWhenItServed = $services->resets;

                return 0;
            });

        // When
        new KeysOpenedFirst(self::kernelHolding(self::opening(new RecordingKeys()), $services), $runner)->run();

        // Then
        static::assertSame(1, $resetWhenItServed);
    }

    #[Test]
    public function aKernelThatHoldsNoOpeningOfAThreadIsRefused(): void
    {
        // Given
        $kernel = self::kernelHolding(new stdClass(), new CountedResets());

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('The service "beffroi.keys.opened_by_a_thread" is what a thread opens at start.');

        // When
        new KeysOpenedFirst($kernel, static::createStub(RunnerInterface::class))->run();
    }

    private static function opening(RecordingKeys $keys): KeysOpenedAtStart
    {
        return new KeysOpenedAtStart(new AmbientTenant(Fixtures::tenant()), [$keys], new RecordedMessages());
    }

    /**
     * Its container, like the one of a kernel, is there once it has booted.
     */
    private static function kernelHolding(object $opening, CountedResets $services): KernelInterface
    {
        $container = new Container();
        $container->set(KeysOpenedAtStart::BY_A_THREAD, $opening);
        $container->set('services_resetter', $services);
        $booted = false;
        $kernel = static::createStub(KernelInterface::class);
        $kernel
            ->method('boot')
            ->willReturnCallback(static function () use (&$booted): void {
                $booted = true;
            });
        $kernel
            ->method('getContainer')
            ->willReturnCallback(static function () use (&$booted, $container): Container {
                return $booted ? $container : throw new LogicException('Cannot retrieve the container from a non-booted kernel.');
            });

        return $kernel;
    }
}
