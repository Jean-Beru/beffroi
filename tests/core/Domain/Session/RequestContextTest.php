<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Domain\Session;

use Heidi\Core\Domain\Session\Device;
use Heidi\Core\Domain\Session\DeviceType;
use Heidi\Core\Domain\Session\GeoLocation;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function mb_strlen;
use function str_repeat;

final class RequestContextTest extends TestCase
{
    #[Test]
    public function itKeepsTheRawValuesAndStartsUnenriched(): void
    {
        // When
        $context = Fixtures::context();

        // Then
        static::assertSame('203.0.113.10', $context->ipAddress);
        static::assertSame('Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0', $context->userAgent);
        static::assertFalse($context->isEnriched());
    }

    #[Test]
    public function anUnknownContextHasNoAddressAndNoUserAgent(): void
    {
        // When
        $context = RequestContext::unknown(Fixtures::now());

        // Then
        static::assertNull($context->ipAddress);
        static::assertNull($context->userAgent);
    }

    #[Test]
    public function itAcceptsAnIpv6Address(): void
    {
        // When
        $context = new RequestContext(Fixtures::now(), '2001:db8::1');

        // Then
        static::assertSame('2001:db8::1', $context->ipAddress);
    }

    #[Test]
    public function itRejectsWhatIsNotAnAddress(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new RequestContext(Fixtures::now(), '203.0.113.256');
    }

    #[Test]
    public function itTrimsTheUserAgent(): void
    {
        // When
        $context = new RequestContext(Fixtures::now(), null, ' curl/8.0 ');

        // Then
        static::assertSame('curl/8.0', $context->userAgent);
    }

    #[Test]
    public function itDropsABlankUserAgent(): void
    {
        // When
        $context = new RequestContext(Fixtures::now(), null, '   ');

        // Then
        static::assertNull($context->userAgent);
    }

    #[Test]
    #[DataProvider('provideUserAgentLengths')]
    public function itBoundsTheUserAgentInCharactersAndNotInBytes(string $userAgent, int $length): void
    {
        // When
        $context = new RequestContext(Fixtures::now(), null, $userAgent);

        // Then
        static::assertSame($length, mb_strlen($context->userAgent ?? ''));
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function provideUserAgentLengths(): iterable
    {
        yield 'multibyte characters' => ['éàü', 3];
        yield 'longer than the bound' => [str_repeat('é', RequestContext::USER_AGENT_MAX_LENGTH + 100), RequestContext::USER_AGENT_MAX_LENGTH];
    }

    /**
     * Enrichment happens later and elsewhere: it produces a new context and leaves the original untouched.
     */
    #[Test]
    public function locatingProducesANewContextAndLeavesTheOriginalUntouched(): void
    {
        // Given
        $raw = Fixtures::context();

        // When
        $located = $raw->withLocation(new GeoLocation(countryCode: 'FR', city: 'Lyon'));

        // Then
        static::assertFalse($raw->isEnriched());
        static::assertTrue($located->isEnriched());
        static::assertSame('FR', $located->location?->countryCode);
        static::assertNull($located->device);
    }

    #[Test]
    public function describingTheDeviceKeepsTheRawValuesAndTheLocation(): void
    {
        // Given
        $raw = Fixtures::context();
        $located = $raw->withLocation(new GeoLocation(countryCode: 'FR', city: 'Lyon'));

        // When
        $described = $located->withDevice(new Device(DeviceType::Desktop, 'Firefox', '140.0', 'Linux'));

        // Then
        static::assertSame('FR', $described->location?->countryCode);
        static::assertSame(DeviceType::Desktop, $described->device?->type);
        static::assertSame($raw->receivedAt, $described->receivedAt);
        static::assertSame($raw->ipAddress, $described->ipAddress);
        static::assertSame($raw->userAgent, $described->userAgent);
    }

    #[Test]
    public function removingTheLocationAndTheDeviceLeavesTheContextUnenriched(): void
    {
        // Given
        $enriched = Fixtures::context()
            ->withLocation(new GeoLocation(countryCode: 'FR', city: 'Lyon'))
            ->withDevice(new Device(DeviceType::Desktop, 'Firefox', '140.0', 'Linux'));

        // When
        $stripped = $enriched->withLocation(null)->withDevice(null);

        // Then
        static::assertFalse($stripped->isEnriched());
    }
}
