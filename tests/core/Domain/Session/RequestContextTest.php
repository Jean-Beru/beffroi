<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Session;

use Beffroi\Core\Domain\Session\Device;
use DateTimeImmutable;
use Beffroi\Core\Domain\Session\DeviceType;
use Beffroi\Core\Domain\Session\GeoLocation;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
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

    /**
     * @param array<string, mixed> $document
     */
    #[Test]
    #[DataProvider('provideDocuments')]
    public function itWritesTheDocumentOneColumnHoldsItAs(RequestContext $context, array $document): void
    {
        // When / Then
        static::assertSame($document, $context->toDocument());
    }

    /**
     * @param array<string, mixed> $document
     */
    #[Test]
    #[DataProvider('provideDocuments')]
    public function itComesBackOutOfItsDocument(RequestContext $context, array $document): void
    {
        // When / Then
        static::assertEquals($context, RequestContext::fromDocument($document));
    }

    /**
     * @return iterable<string, array{RequestContext, array<string, mixed>}>
     */
    public static function provideDocuments(): iterable
    {
        yield 'a provenance nothing has enriched' => [
            new RequestContext(new DateTimeImmutable('2026-09-20 14:35:07'), '203.0.113.7', 'curl/8.18.0'),
            [
                'received_at' => '2026-09-20 14:35:07',
                'ip_address' => '203.0.113.7',
                'user_agent' => 'curl/8.18.0',
                'location' => null,
                'device' => null,
            ],
        ];
        yield 'a provenance the enrichment answered' => [
            new RequestContext(
                new DateTimeImmutable('2026-09-20 14:35:07'),
                '203.0.113.7',
                'Mozilla/5.0 Firefox/140.0',
                new GeoLocation('FR', null, 'Paris'),
                new Device(DeviceType::Desktop, 'Firefox'),
            ),
            [
                'received_at' => '2026-09-20 14:35:07',
                'ip_address' => '203.0.113.7',
                'user_agent' => 'Mozilla/5.0 Firefox/140.0',
                'location' => [
                    'country_code' => 'FR',
                    'region' => null,
                    'city' => 'Paris',
                    'asn' => null,
                    'as_organization' => null,
                    'latitude' => null,
                    'longitude' => null,
                ],
                'device' => [
                    'type' => 'desktop',
                    'browser' => 'Firefox',
                    'browser_version' => null,
                    'platform' => null,
                    'platform_version' => null,
                ],
            ],
        ];
        yield 'a provenance that knows nothing of where it came from' => [
            RequestContext::unknown(new DateTimeImmutable('2026-09-20 14:35:07')),
            [
                'received_at' => '2026-09-20 14:35:07',
                'ip_address' => null,
                'user_agent' => null,
                'location' => null,
                'device' => null,
            ],
        ];
    }

    #[Test]
    public function theMomentIsWrittenToTheSecond(): void
    {
        // Given
        $context = RequestContext::unknown(new DateTimeImmutable('2026-09-20 14:35:07.123456'));

        // When / Then
        static::assertSame('2026-09-20 14:35:07', $context->toDocument()['received_at']);
    }

    /**
     * @param array<array-key, mixed> $document
     */
    #[Test]
    #[DataProvider('provideDocumentsThatAreNotAProvenance')]
    public function aDocumentThatIsNotAProvenanceIsRefused(array $document, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        RequestContext::fromDocument($document);
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>, string}>
     */
    public static function provideDocumentsThatAreNotAProvenance(): iterable
    {
        yield 'no moment' => [
            [
                'ip_address' => '203.0.113.7',
            ],
            'A request context says when the request was received.',
        ];
        yield 'a moment that is not one' => [
            [
                'received_at' => 'yesterday afternoon',
            ],
            '"yesterday afternoon" is not when a request was received.',
        ];
        yield 'a numeric address' => [
            [
                'received_at' => '2026-09-20 14:35:07',
                'ip_address' => 203,
            ],
            'The member "ip_address" must be a string or absent.',
        ];
        yield 'an address that is not one' => [
            [
                'received_at' => '2026-09-20 14:35:07',
                'ip_address' => 'somewhere',
            ],
            '"somewhere" is not an IP address.',
        ];
        yield 'a place that is not an object' => [
            [
                'received_at' => '2026-09-20 14:35:07',
                'location' => 'Paris',
            ],
            'The member "location" must be a JSON object, got string.',
        ];
        yield 'a device that is not an object' => [
            [
                'received_at' => '2026-09-20 14:35:07',
                'device' => 'desktop',
            ],
            'The member "device" must be a JSON object, got string.',
        ];
    }
}
