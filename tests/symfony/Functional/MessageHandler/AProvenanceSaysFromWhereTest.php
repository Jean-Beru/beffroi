<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\MessageHandler;

use App\Geo\GeoLite2Databases;
use App\Tests\Symfony\Fixture\MaxMindDatabase;
use App\Tests\Symfony\Functional\Doctrine\DatabaseTestCase;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\RawRows;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\SealedRows;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Doctrine\DBAL\Connection;
use PHPUnit\Framework\Attributes\Test;
use function is_string;
use function sprintf;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Issue #473: a provenance says from where, and not only from which address. The whole of it on the lane,
 * from the event a login announces to the two rows a reader of their own account looks at: the session
 * open in their name, and the act of the journal that says they signed in.
 *
 * The databases are written by the test and not downloaded: what is played here is that the enrichment
 * runs where the architecture says it runs, off the request, and that what it found reaches the sealed
 * column of each row.
 */
final class AProvenanceSaysFromWhereTest extends DatabaseTestCase
{
    /**
     * Every test of this class starts where an installation starts, holding no database at all: the
     * storage of the test kernel is a directory of its cache, which lives as long as the process.
     */
    protected function setUp(): void
    {
        parent::setUp();
        new Filesystem()->remove(self::storage());
    }

    /**
     * The place of the address is written on both provenances of the session, after the row was already
     * written: the login of a browser never waits for a database of addresses.
     */
    #[Test]
    public function theProvenancesOfASessionSayThePlaceOfTheirAddress(): void
    {
        // Given
        self::holdingTheDatabases();
        $session = self::session(self::user('alice'));

        // When
        self::announce($session);

        // Then
        $read = self::sessions()->find($session->id);
        static::assertInstanceOf(AuthenticationSession::class, $read);
        static::assertSame('Oxford', $read->createdFrom->location?->city);
        static::assertSame('Oxfordshire', $read->createdFrom->location->region);
        static::assertSame('GB', $read->createdFrom->location->countryCode);
        static::assertSame(64_268, $read->createdFrom->location->autonomousSystemNumber);
        static::assertSame('Oxford', $read->lastSeenFrom->location?->city);
    }

    /**
     * And the act the journal wrote down for the same event, which is the other row a person reads: it
     * says the place the day it is written, the handler of the journal being on that same lane.
     */
    #[Test]
    public function anActOfTheJournalSaysThePlaceOfItsAddress(): void
    {
        // Given
        self::holdingTheDatabases();
        $session = self::session(self::user('alice'));

        // When
        self::announce($session);

        // Then
        static::assertSame('Oxford', self::onlyAct()->context->location?->city);
    }

    /**
     * The place is a personal datum of the person it is about, so it is sealed where the address beside it
     * is sealed (decisions 0011 and 0018): the row of the journal holds nothing of it in the clear.
     */
    #[Test]
    public function theRowOfTheJournalHoldsNothingOfThePlaceInTheClear(): void
    {
        // Given
        self::holdingTheDatabases();
        $session = self::session(self::user('alice'));

        // When
        self::announce($session);

        // Then
        static::assertStringNotContainsString('Oxford', self::provenanceOfTheOnlyAct());
    }

    /**
     * A deployment that never refreshed a database serves the same login and says the same address, with
     * no place and no row rewritten (`GeoLite2GeoLocator`).
     */
    #[Test]
    public function aDeploymentThatHoldsNoDatabaseSaysTheAddressAlone(): void
    {
        // Given
        $session = self::session(self::user('alice'));

        // When
        self::announce($session);

        // Then
        $read = self::sessions()->find($session->id);
        static::assertInstanceOf(AuthenticationSession::class, $read);
        static::assertSame(SealedRows::IP_ADDRESS, $read->createdFrom->ipAddress);
        static::assertFalse($read->createdFrom->isEnriched());
        static::assertNull(self::onlyAct()->context->location);
    }

    /**
     * The provenance of the one act, as the database holds it, which is what an operator or a dump would
     * see. A column that holds nothing fails here rather than letting the search pass for the wrong reason.
     */
    private static function provenanceOfTheOnlyAct(): string
    {
        $rows = RawRows::of(self::connection(), 'beffroi_journal', ['context']);
        static::assertCount(1, $rows);

        return $rows[0]['context'] ?? static::fail('The act of the journal holds no provenance at all.');
    }

    /**
     * Where the provider reads the databases of addresses, read from the container rather than restated, so
     * that it is the directory the kernel of this process was given, token of a parallel worker included.
     */
    private static function storage(): string
    {
        $cacheDirectory = static::getContainer()->getParameter('kernel.cache_dir');
        if (! is_string($cacheDirectory)) {
            static::fail('The cache directory of the test kernel is not a path.');
        }

        return $cacheDirectory . '/geoip';
    }

    private static function holdingTheDatabases(): void
    {
        $databases = self::service('test.beffroi.geoip_databases', GeoLite2Databases::class);
        new Filesystem()->mkdir(self::storage());
        $databases->write(GeoLite2Databases::CITY, MaxMindDatabase::inFile(MaxMindDatabase::city(), self::storage()));
        $databases->write(GeoLite2Databases::ASN, MaxMindDatabase::inFile(MaxMindDatabase::asn(), self::storage()));
    }

    private static function announce(AuthenticationSession $session): void
    {
        self::service('event.bus', MessageBusInterface::class)->dispatch(new UserAuthenticated($session));
        self::reload();
    }

    private static function sessions(): AuthenticationSessionRepositoryInterface
    {
        return self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class);
    }

    private static function onlyAct(): JournalEntry
    {
        $id = self::connection()->fetchOne('SELECT id FROM beffroi_journal');
        static::assertIsString($id, 'The act was not written down.');

        return self::entityManager()->find(JournalEntry::class, Uuid::fromString($id)) ?? static::fail(sprintf('The act "%s" cannot be read back.', $id));
    }

    private static function connection(): Connection
    {
        return self::entityManager()->getConnection();
    }
}
