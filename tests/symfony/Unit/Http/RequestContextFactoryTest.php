<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Http;

use DateTimeImmutable;
use Heidi\Bundle\Http\RequestContextFactory;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpFoundation\Request;

/**
 * Architecture §3.5: the context of a request, as received, not enriched.
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
}
