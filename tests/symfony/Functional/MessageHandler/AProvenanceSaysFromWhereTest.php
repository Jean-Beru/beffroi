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

final class AProvenanceSaysFromWhereTest extends DatabaseTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        new Filesystem()->remove(self::storage());
    }

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

    private static function provenanceOfTheOnlyAct(): string
    {
        $rows = RawRows::of(self::connection(), 'beffroi_journal', ['context']);
        static::assertCount(1, $rows);

        return $rows[0]['context'] ?? static::fail('The act of the journal holds no provenance at all.');
    }

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
