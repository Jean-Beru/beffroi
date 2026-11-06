<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Runtime;

use App\Runtime\KeysOpenedFirst;
use App\Runtime\Runtime;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * Decision 0018
 */
final class RuntimeTest extends TestCase
{
    protected function tearDown(): void
    {
        unset($_SERVER['FRANKENPHP_WORKER']);
    }

    #[Test]
    public function aWorkerThreadOfFrankenPhpOpensItsKeysBeforeItServes(): void
    {
        // Given
        $_SERVER['FRANKENPHP_WORKER'] = '1';

        // When
        $runner = self::runtime()->getRunner(static::createStub(KernelInterface::class));

        // Then
        static::assertInstanceOf(KeysOpenedFirst::class, $runner);
    }

    #[Test]
    #[DataProvider('provideWhatOpensNothingAhead')]
    public function whatIsNoKernelInAWorkerThreadIsRunAsSymfonyRunsIt(bool $worker, ?Response $response): void
    {
        // Given
        if ($worker) {
            $_SERVER['FRANKENPHP_WORKER'] = '1';
        }

        // When
        $runner = self::runtime()->getRunner($response ?? static::createStub(KernelInterface::class));

        // Then
        static::assertNotInstanceOf(KeysOpenedFirst::class, $runner);
    }

    /**
     * @return iterable<string, array{bool, Response|null}>
     */
    public static function provideWhatOpensNothingAhead(): iterable
    {
        yield 'a kernel that serves one request' => [false, null];
        yield 'a response a worker thread answers' => [true, new Response()];
    }

    private static function runtime(): Runtime
    {
        return new Runtime([
            'env' => 'test',
            'debug' => false,
            'disable_dotenv' => true,
            'error_handler' => false,
        ]);
    }
}
