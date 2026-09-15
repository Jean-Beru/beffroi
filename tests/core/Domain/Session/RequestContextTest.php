<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Domain\Session;

use Heidi\Core\Domain\Session\Device;
use Heidi\Core\Domain\Session\DeviceType;
use Heidi\Core\Domain\Session\GeoLocation;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

final class RequestContextTest extends TestCase
{
    #[Test]
    public function itKeepsTheRawValuesAndStartsUnenriched(): void
    {
        $context = Fixtures::context();

        static::assertSame('203.0.113.10', $context->ipAddress);
        static::assertSame('Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0', $context->userAgent);
        static::assertFalse($context->isEnriched());
        static::assertNull(RequestContext::unknown(Fixtures::now())->ipAddress);
    }

    #[Test]
    public function itAcceptsIpv6AndRejectsWhatIsNotAnAddress(): void
    {
        static::assertSame('2001:db8::1', (new RequestContext(Fixtures::now(), '2001:db8::1'))->ipAddress);

        $this->expectException(InvalidArgumentException::class);
        new RequestContext(Fixtures::now(), '203.0.113.256');
    }

    #[Test]
    public function itTrimsTheUserAgentDropsAnEmptyOneAndBoundsItsLength(): void
    {
        static::assertNull((new RequestContext(Fixtures::now(), null, '   '))->userAgent);
        static::assertSame('curl/8.0', (new RequestContext(Fixtures::now(), null, ' curl/8.0 '))->userAgent);
        static::assertSame(RequestContext::USER_AGENT_MAX_LENGTH, new RequestContext(Fixtures::now(), null, str_repeat('é', RequestContext::USER_AGENT_MAX_LENGTH + 100))->userAgentLength());
        static::assertSame(3, new RequestContext(Fixtures::now(), null, 'éàü')->userAgentLength());
        static::assertSame(0, RequestContext::unknown(Fixtures::now())->userAgentLength());
    }

    /**
     * Enrichment happens later and elsewhere: it produces a new context and leaves the original untouched.
     */
    #[Test]
    public function enrichmentIsImmutable(): void
    {
        $raw = Fixtures::context();

        $located = $raw->withLocation(new GeoLocation(countryCode: 'FR', city: 'Lyon'));
        $described = $located->withDevice(new Device(DeviceType::Desktop, 'Firefox', '140.0', 'Linux'));

        static::assertFalse($raw->isEnriched());
        static::assertTrue($located->isEnriched());
        static::assertNull($located->device);
        static::assertSame('FR', $described->location?->countryCode);
        static::assertSame(DeviceType::Desktop, $described->device?->type);
        static::assertSame($raw->receivedAt, $described->receivedAt);
        static::assertSame($raw->ipAddress, $described->ipAddress);
        static::assertSame($raw->userAgent, $described->userAgent);
        static::assertFalse($described->withLocation(null)->withDevice(null)->isEnriched());
    }
}
