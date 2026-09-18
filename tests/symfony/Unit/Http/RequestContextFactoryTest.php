<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Http;

use DateTimeImmutable;
use function gethostname;
use Heidi\Bundle\Http\RequestContextFactory;
use PHPUnit\Framework\Attributes\BackupGlobals;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpFoundation\Request;

/**
 * Architecture §3.5: the context of a request, as received, not enriched; the context of a process that is
 * no request, saying what it is.
 */
final class RequestContextFactoryTest extends TestCase
{
    #[Test]
    public function theContextIsTheMomentTheClientIpAndTheUserAgent(): void
    {
        // Given
        $now = new DateTimeImmutable('2026-09-15T10:00:00+00:00');
        $factory = new RequestContextFactory(new MockClock($now));
        $request = Request::create('/authorize', 'GET', server: [
            'REMOTE_ADDR' => '203.0.113.10',
            'HTTP_USER_AGENT' => 'Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0',
        ]);

        // When
        $context = $factory->fromRequest($request);

        // Then
        static::assertEquals($now, $context->receivedAt);
        static::assertSame('203.0.113.10', $context->ipAddress);
        static::assertSame('Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0', $context->userAgent);
        static::assertFalse($context->isEnriched());
    }

    #[Test]
    public function aRequestWithoutAnAddressOrAnAgentIsStillAContext(): void
    {
        // Given
        $factory = new RequestContextFactory(new MockClock());
        $request = Request::create('/authorize');
        $request->server->remove('REMOTE_ADDR');
        $request->headers->remove('User-Agent');

        // When
        $context = $factory->fromRequest($request);

        // Then
        static::assertNull($context->ipAddress);
        static::assertNull($context->userAgent);
    }

    /**
     * The console names its command and the user of the shell, so that the trail says who rotated a key.
     */
    #[Test]
    #[BackupGlobals(true)]
    public function theConsoleNamesItsCommandAndTheUserOfTheShell(): void
    {
        // Given
        $now = new DateTimeImmutable('2026-09-15T10:00:00+00:00');
        $factory = new RequestContextFactory(new MockClock($now));
        $_SERVER['SUDO_USER'] = 'alice';
        $_SERVER['USER'] = 'root';

        // When
        $context = $factory->fromConsole('heidi:keys:rotate');

        // Then
        static::assertEquals($now, $context->receivedAt);
        static::assertNull($context->ipAddress);
        static::assertSame(sprintf('heidi-console/heidi:keys:rotate (alice@%s)', self::host()), $context->userAgent);
    }

    #[Test]
    #[BackupGlobals(true)]
    public function theConsoleNamesTheUserOfTheShellWhenNobodySudoed(): void
    {
        // Given
        $factory = new RequestContextFactory(new MockClock());
        unset($_SERVER['SUDO_USER']);
        $_SERVER['USER'] = 'bob';

        // When
        $context = $factory->fromConsole('heidi:keys:rotate');

        // Then
        static::assertStringStartsWith('heidi-console/heidi:keys:rotate (bob@', $context->userAgent ?? '');
    }

    #[Test]
    public function theSchedulerNamesItsSchedule(): void
    {
        // Given
        $factory = new RequestContextFactory(new MockClock());

        // When
        $context = $factory->fromSchedule('heidi');

        // Then
        static::assertNull($context->ipAddress);
        static::assertSame(sprintf('heidi-scheduler/heidi (%s)', self::host()), $context->userAgent);
    }

    private static function host(): string
    {
        $host = gethostname();
        static::assertIsString($host);

        return $host;
    }
}
