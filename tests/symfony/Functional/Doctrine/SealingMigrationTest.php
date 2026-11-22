<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;
use Doctrine\Migrations\Exception\AbortMigration;
use DoctrineMigrations\Version20261001180000;
use DoctrineMigrations\Version20261002120000;
use App\Tests\Symfony\Fixture\RecordedMessages;
use Beffroi\Core\Domain\Identity\LinkedIdentity;
use Beffroi\Core\Port\LinkedIdentityRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use Psr\Log\NullLogger;
use Symfony\Component\Uid\Uuid;
use function implode;

/**
 * Decision 0011
 */
final class SealingMigrationTest extends DatabaseTestCase
{
    #[Test]
    public function aTableThatHoldsRowsIsRefusedWithTheTwoWaysOut(): void
    {
        // Given
        self::user();
        $migration = self::migration(Version20261001180000::class);

        // Then
        $this->expectException(AbortMigration::class);
        $this->expectExceptionMessageIsOrContains('beffroi_user holds 1 row(s) and this migration seals its columns');

        // When
        $migration->preUp(new Schema());
    }

    #[Test]
    public function theSentenceSaysThereIsNoMigrationPathAndHowToEmptyTheTable(): void
    {
        // Given
        self::user();
        $migration = self::migration(Version20261001180000::class);

        // When
        try {
            $migration->preUp(new Schema());
            static::fail('A table that holds rows was not refused.');
        } catch (AbortMigration $refusal) {
            // Then
            static::assertStringContainsString('There is no migration path for cleartext rows', $refusal->getMessage());
            static::assertStringContainsString('TRUNCATE TABLE beffroi_user CASCADE', $refusal->getMessage());
        }
    }

    #[Test]
    public function theMigrationOfTheLinkedIdentitiesNamesItsOwnTable(): void
    {
        // Given
        self::linkedIdentity();
        $migration = self::migration(Version20261002120000::class);

        // Then
        $this->expectException(AbortMigration::class);
        $this->expectExceptionMessageIsOrContains('beffroi_linked_identity holds 1 row(s) and this migration seals its columns');

        // When
        $migration->preUp(new Schema());
    }

    #[Test]
    public function anEmptyTableIsNotRefused(): void
    {
        // Given
        $migration = self::migration(Version20261002120000::class);

        // When
        $migration->preUp(new Schema());

        // Then
        static::assertSame([], $migration->getSql());
    }

    #[Test]
    public function goingBackOnATableThatHoldsRowsIsRefusedToo(): void
    {
        // Given
        self::user();
        $migration = self::migration(Version20261001180000::class);

        // Then
        $this->expectException(AbortMigration::class);
        $this->expectExceptionMessageIsOrContains('this migration unseals its columns');

        // When
        $migration->preDown(new Schema());
    }

    #[Test]
    public function theWordsSayToRestartWhatReadsTheColumnsAndThatOneCaseIsSilent(): void
    {
        // Given
        $said = new RecordedMessages();
        $migration = self::migration(Version20261002120000::class, $said);

        // When
        $migration->preUp(new Schema());

        // Then
        $notices = implode("\n", $said->at(LogLevel::NOTICE));
        static::assertStringContainsString(
            'A process that booted before this migration reads the columns of beffroi_linked_identity with the type they had, so restart what serves requests and what consumes the bus once it has run.',
            $notices,
        );
        static::assertStringContainsString('a column typed "text" does not, and returns the ciphertext as a string', $notices);
    }

    #[Test]
    public function goingBackSaysToRestartThemToo(): void
    {
        // Given
        $said = new RecordedMessages();
        $migration = self::migration(Version20261002120000::class, $said);

        // When
        $migration->preDown(new Schema());

        // Then
        static::assertStringContainsString(
            'reads the columns of beffroi_linked_identity with the type they had',
            implode("\n", $said->at(LogLevel::NOTICE)),
        );
    }

    /**
     * @param class-string<AbstractMigration> $migration
     */
    private static function migration(string $migration, ?LoggerInterface $logger = null): AbstractMigration
    {
        return new $migration(self::entityManager()->getConnection(), $logger ?? new NullLogger());
    }

    private static function linkedIdentity(): void
    {
        self::service('test.beffroi.linked_identities', LinkedIdentityRepositoryInterface::class)
            ->save(
                new LinkedIdentity(
                    Uuid::v7(),
                    self::user(),
                    'login.acme-federation.example',
                    '110169484474386276334',
                    [
                        'email' => 'ada@example.org',
                    ],
                    self::now(),
                    self::now(),
                ),
            );
    }
}
