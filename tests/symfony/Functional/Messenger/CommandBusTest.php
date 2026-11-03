<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Messenger;

use Beffroi\Bundle\Message\SendLogoutToken;
use Beffroi\Bundle\Tests\Functional\Doctrine\DatabaseTestCase;
use Beffroi\Core\Domain\Identity\Subject;
use Closure;
use const E_DEPRECATED;
use const E_USER_DEPRECATED;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\Attributes\Test;
use function restore_error_handler;
use function set_error_handler;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Issue #925: what the command bus runs a message through is built the first time a process puts a message
 * on it, so a middleware whose class its package deprecates raises its deprecation in every process that
 * dispatches, the worker of each lane and the scheduler at its first step among them.
 */
final class CommandBusTest extends DatabaseTestCase
{
    /**
     * The container is compiled here, in the process of the suite, before the process of the test reads
     * it: PHPUnit calls this method in both. Compiling it loads the classes of the middleware, and a class
     * raises its deprecation once, when it is loaded, so a test whose own process compiled the container
     * would find every deprecation raised already. A deployment is in the same place: its image carries the
     * container compiled, and its worker builds the bus.
     */
    public static function setUpBeforeClass(): void
    {
        self::bootKernel();
        self::ensureKernelShutdown();
    }

    /**
     * A process of its own, because the process of the suite built the bus long before this test. The
     * message is one the bus sends to a lane and that nothing handles here, so that what runs is the
     * middleware of the bus and nothing else: the lane of the notifications is a queue in memory in the
     * test kernel.
     */
    #[Test]
    #[RunInSeparateProcess]
    public function theFirstMessageAProcessPutsOnTheBusRaisesNoDeprecation(): void
    {
        // Given
        $bus = self::service('command.bus', MessageBusInterface::class);
        $message = new SendLogoutToken(
            self::tenant(),
            'oidc-demo',
            'https://demo.test/backchannel-logout',
            'a-logout-token',
            Uuid::fromString('0192f0a4-8e1b-7c3d-9a2b-4c5d6e7f8091'),
            new Subject('alice-subject'),
            self::context(),
        );

        // When
        $deprecations = self::deprecationsRaisedWhile(static fn (): object => $bus->dispatch($message));

        // Then
        static::assertSame([], $deprecations);
    }

    /**
     * Every deprecation raised while the call runs, the ones "@" silences included: a class of Symfony
     * raises its deprecation silenced (trigger_deprecation()), and the error handler of the kernel still
     * writes it to the "deprecation" channel, which is where a deployment reads it.
     *
     * @param Closure(): mixed $call
     *
     * @return list<string>
     */
    private static function deprecationsRaisedWhile(Closure $call): array
    {
        $deprecations = [];
        set_error_handler(static function (int $level, string $message) use (&$deprecations): bool {
            $deprecations[] = $message;

            return true;
        }, E_DEPRECATED | E_USER_DEPRECATED);
        try {
            $call();
        } finally {
            restore_error_handler();
        }

        return $deprecations;
    }
}
