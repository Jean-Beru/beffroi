<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Geo;

use Beffroi\Bundle\Geo\GeoLite2Databases;
use Beffroi\Bundle\Geo\GeoLite2GeoLocator;
use Beffroi\Bundle\Tests\Fixture\MaxMindDatabase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use function sys_get_temp_dir;
use Symfony\Component\Filesystem\Filesystem;
use function uniqid;

/**
 * Issue #473: the place of an address, read in the two GeoLite2 editions of the deployment and nowhere
 * else.
 */
final class GeoLite2GeoLocatorTest extends TestCase
{
    private string $directory;

    private GeoLite2Databases $databases;

    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir() . '/beffroi-bundle-tests/geoip-' . uniqid();
        new Filesystem()->mkdir($this->directory);
        $this->databases = new GeoLite2Databases($this->directory);
    }

    protected function tearDown(): void
    {
        new Filesystem()->remove($this->directory);
    }

    /**
     * The seven fields of a GeoLocation, four from the city edition and two from the ASN edition, the
     * region being the most specific subdivision the record holds.
     */
    #[Test]
    public function theTwoEditionsTogetherSayTheSevenThingsAPlaceIs(): void
    {
        // Given
        $this->holding(MaxMindDatabase::city(), MaxMindDatabase::asn());

        // When
        $place = $this->locator()->locate(MaxMindDatabase::KNOWN_ADDRESS);

        // Then
        static::assertSame('GB', $place?->countryCode);
        static::assertSame('Oxfordshire', $place->region);
        static::assertSame('Oxford', $place->city);
        static::assertSame(64_268, $place->autonomousSystemNumber);
        static::assertSame('Example Networks', $place->autonomousSystemOrganization);
        static::assertSame(51.752, $place->latitude);
        static::assertSame(-1.2577, $place->longitude);
    }

    /**
     * A deployment that never ran the refresh holds nothing, and says no place rather than failing: every
     * flow is served, with a provenance that says an address alone.
     */
    #[Test]
    public function aDeploymentThatHoldsNoDatabaseSaysNoPlace(): void
    {
        // When
        $place = $this->locator()->locate(MaxMindDatabase::KNOWN_ADDRESS);

        // Then
        static::assertNull($place);
    }

    /**
     * An address in no network of the editions is the same answer, and it is the common one: a database
     * of addresses covers the public internet and not a desk.
     */
    #[Test]
    public function anAddressNoNetworkOfTheDatabasesCoversSaysNoPlace(): void
    {
        // Given
        $this->holding(MaxMindDatabase::city(), MaxMindDatabase::asn());

        // When
        $place = $this->locator()->locate(MaxMindDatabase::UNKNOWN_ADDRESS);

        // Then
        static::assertNull($place);
    }

    /**
     * One edition alone answers what that edition carries: the two are stored by the same command and a
     * deployment may still hold one of them.
     *
     * @param array{?string, ?int} $expected the city of the place and the number of its autonomous system
     */
    #[Test]
    #[DataProvider('provideSingleEditions')]
    public function oneEditionAloneAnswersWhatItCarries(bool $city, bool $asn, array $expected): void
    {
        // Given
        $this->holding($city ? MaxMindDatabase::city() : null, $asn ? MaxMindDatabase::asn() : null);

        // When
        $place = $this->locator()->locate(MaxMindDatabase::KNOWN_ADDRESS);

        // Then
        static::assertSame($expected, [$place?->city, $place?->autonomousSystemNumber]);
    }

    /**
     * @return iterable<string, array{bool, bool, array{?string, ?int}}>
     */
    public static function provideSingleEditions(): iterable
    {
        yield 'the city edition alone' => [true, false, ['Oxford', null]];
        yield 'the ASN edition alone' => [false, true, [null, 64_268]];
    }

    /**
     * A file that is not a database loses a place and nothing else: what fails is an enrichment, on a
     * lane, behind a login that has already happened.
     */
    #[Test]
    public function aDatabaseThatCannotBeReadSaysNoPlace(): void
    {
        // Given
        $this->holding('not a database at all', MaxMindDatabase::asn());

        // When
        $place = $this->locator()->locate(MaxMindDatabase::KNOWN_ADDRESS);

        // Then
        static::assertSame(64_268, $place?->autonomousSystemNumber);
        static::assertNull($place->city);
    }

    /**
     * A record whose country code is not a country code: the place is given up rather than written down
     * wrong, and nothing of it reaches the row.
     */
    #[Test]
    public function aRecordTheDomainRefusesSaysNoPlace(): void
    {
        // Given
        $this->holding(MaxMindDatabase::of(MaxMindDatabase::CITY_EDITION, [
            'country' => [
                'iso_code' => 'gb',
            ],
        ]), null);

        // When
        $place = $this->locator()->locate(MaxMindDatabase::KNOWN_ADDRESS);

        // Then
        static::assertNull($place);
    }

    private function holding(?string $city, ?string $asn): void
    {
        if ($city !== null) {
            $this->databases->write(GeoLite2Databases::CITY, MaxMindDatabase::inFile($city, $this->directory));
        }
        if ($asn !== null) {
            $this->databases->write(GeoLite2Databases::ASN, MaxMindDatabase::inFile($asn, $this->directory));
        }
    }

    private function locator(): GeoLite2GeoLocator
    {
        return new GeoLite2GeoLocator($this->databases, new NullLogger());
    }
}
