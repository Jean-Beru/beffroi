<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;
use Doctrine\Migrations\Exception\AbortMigration;
use Heidi\Bundle\Migrations\Version20261001180000;
use Heidi\Bundle\Migrations\Version20261002120000;
use Heidi\Core\Domain\Identity\LinkedIdentity;
use Heidi\Core\Port\LinkedIdentityRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use Psr\Log\NullLogger;
use Symfony\Component\Uid\Uuid;

/**
 * What an operator reads when a migration that seals a table meets a table that holds rows.
 *
 * The refusal itself is intended: a sealed column is binary and accepts no null, so a row whose values are
 * in the clear has nothing to become, and decision 0011 settled that there is no migration path for such
 * rows, no deployment existing. What this holds is the sentence, because without it the server answers
 * with a null violation on a column nobody made nullable and says nothing about what to do.
 *
 * It runs on `preUp()`, which the executor of the migrations calls before `up()` and which nothing of
 * MigrationTest calls, that test comparing the DDL of every migration with the mappings without a database
 * at all.
 */
final class SealingMigrationTest extends DatabaseTestCase
{
    /**
     * The sentence names the table, how many rows it holds, and the two ways out: an operator running
     * several of these knows which table to empty and what emptying it means.
     */
    #[Test]
    public function aTableThatHoldsRowsIsRefusedWithTheTwoWaysOut(): void
    {
        // Given
        self::user();
        $migration = self::migration(Version20261001180000::class);

        // Then
        $this->expectException(AbortMigration::class);
        $this->expectExceptionMessageIsOrContains('heidi_user holds 1 row(s) and this migration seals its columns');

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
            static::assertStringContainsString('TRUNCATE TABLE heidi_user CASCADE', $refusal->getMessage());
        }
    }

    /**
     * Every migration of this kind, and not only the first: each one names the table it recreates columns
     * of, and a migration that named none would refuse nothing at all.
     */
    #[Test]
    public function theMigrationOfTheLinkedIdentitiesNamesItsOwnTable(): void
    {
        // Given
        self::linkedIdentity();
        $migration = self::migration(Version20261002120000::class);

        // Then
        $this->expectException(AbortMigration::class);
        $this->expectExceptionMessageIsOrContains('heidi_linked_identity holds 1 row(s) and this migration seals its columns');

        // When
        $migration->preUp(new Schema());
    }

    /**
     * An empty table is what every migration of this kind expects, and it says nothing then.
     */
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

    /**
     * Going back is refused for the same reason and not the opposite one: nothing unseals a value, so a row
     * would come back out of a column that no longer holds its ciphertext.
     */
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

    /**
     * @param class-string<AbstractMigration> $migration
     */
    private static function migration(string $migration): AbstractMigration
    {
        return new $migration(self::entityManager()->getConnection(), new NullLogger());
    }

    private static function linkedIdentity(): void
    {
        self::service('test.heidi.linked_identities', LinkedIdentityRepositoryInterface::class)
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
