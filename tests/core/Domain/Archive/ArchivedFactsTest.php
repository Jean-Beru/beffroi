<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Archive;

use Beffroi\Core\Domain\Archive\ArchivedFacts;
use Beffroi\Core\Domain\Session\Device;
use Beffroi\Core\Domain\Session\DeviceType;
use Beffroi\Core\Domain\Session\GeoLocation;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Issue #453: the readings every chapter of an archive shares, so that two chapters writing the same fact
 * write it the same way and a reader of the file learns one shape.
 */
final class ArchivedFactsTest extends TestCase
{
    /**
     * The shape of RFC 3339, which is what RGPD article 20 means by machine readable.
     */
    #[Test]
    public function aMomentIsWrittenInTheShapeOfTheSpecification(): void
    {
        // When / Then
        static::assertSame('2026-09-15T10:00:00+00:00', ArchivedFacts::moment(Fixtures::now()));
    }

    #[Test]
    public function aMomentThisProviderHoldsNoneOfIsNone(): void
    {
        // When / Then
        static::assertNull(ArchivedFacts::moment(null));
    }

    #[Test]
    public function aProvenanceIsTheAddressAndTheUserAgentAsTheyReachedTheProvider(): void
    {
        // When
        $facts = ArchivedFacts::context(Fixtures::context());

        // Then
        static::assertSame(Fixtures::context()->ipAddress, $facts['ip_address']);
        static::assertSame(Fixtures::context()->userAgent, $facts['user_agent']);
        static::assertSame('2026-09-15T10:00:00+00:00', $facts['received_at']);
    }

    /**
     * What the enrichment made of an address is in the file because it is a personal datum this provider
     * holds, which is the whole question article 15 asks.
     */
    #[Test]
    public function aProvenanceThatWasEnrichedCarriesWhereAndWhatFrom(): void
    {
        // Given
        $context = Fixtures::context()
            ->withLocation(new GeoLocation('FR', 'Grand Est', 'Strasbourg', 64476, 'Example Telecom', 48.5839, 7.7455))
            ->withDevice(new Device(DeviceType::Mobile, 'Firefox', '140.0', 'Android', '15'));

        // When
        $facts = ArchivedFacts::context($context);

        // Then
        static::assertSame(
            [
                'country_code' => 'FR',
                'region' => 'Grand Est',
                'city' => 'Strasbourg',
                'autonomous_system_number' => 64476,
                'autonomous_system_organization' => 'Example Telecom',
                'latitude' => 48.5839,
                'longitude' => 7.7455,
            ],
            $facts['location'],
        );
        static::assertSame(
            [
                'type' => 'mobile',
                'browser' => 'Firefox',
                'browser_version' => '140.0',
                'platform' => 'Android',
                'platform_version' => '15',
            ],
            $facts['device'],
        );
    }

    /**
     * The enrichment is asynchronous, so a provenance a run of it never reached says so rather than
     * saying nothing of where a request came from.
     */
    #[Test]
    public function aProvenanceThatWasNotEnrichedCarriesNeither(): void
    {
        // When
        $facts = ArchivedFacts::context(Fixtures::context());

        // Then
        static::assertNull($facts['location']);
        static::assertNull($facts['device']);
    }
}
