<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use function array_filter;
use function array_keys;
use function array_values;
use function bin2hex;
use Doctrine\DBAL\Connection;
use function file_put_contents;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\ClassifiedModel;
use Beffroi\Core\Domain\PersonalData\Sealed;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\SealedRows;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\SearchedDump;
use function implode;
use function is_numeric;
use function is_string;
use function json_encode;
use PHPUnit\Framework\Attributes\Test;
use function random_bytes;
use function sort;
use function sprintf;
use function strlen;
use function unlink;

/**
 * The first success criterion of spike 8: a dump of the database gives nothing away.
 *
 * One row of every family the classification seals is written, and then the database is searched byte by
 * byte for every value that went in. It searches the file and not the rows, because a backup carries the
 * indexes, the pages a row was deleted from and the journal as much as it carries the columns.
 *
 * This half says the types seal. It does not say what the database of a deployment holds: the suite runs on
 * SQLite, and PostgreSQL stores a sealed column as `BYTEA` with its own pages and its own write-ahead log.
 * The walk against the running stack is what answers that, and the two are not interchangeable.
 */
final class DumpGivesNothingAwayTest extends DatabaseTestCase
{
    /**
     * The criterion itself.
     */
    #[Test]
    public function aDumpOfTheDatabaseGivesNoneOfTheValuesTheFixtureWroteAway(): void
    {
        // Given
        self::rows();

        // When
        $findings = self::dump()->findings(self::connection(), SealedRows::searchable());

        // Then
        static::assertSame([], $findings, implode("\n", $findings));
    }

    /**
     * What makes the criterion mean something: a value added to a sealed column later is searched for
     * without anyone remembering to add it, because the model is what says which columns are
     * sealed and this holds the fixture to what it declares.
     */
    #[Test]
    public function theFixtureWritesAValueIntoEveryColumnTheClassificationSeals(): void
    {
        // Given
        $sealed = [];
        foreach (ClassifiedModel::of(self::entityManager())->columns() as $table => $columns) {
            foreach ($columns as $column => $line) {
                if ($line instanceof Sealed) {
                    $sealed[] = sprintf('%s.%s', $table, $column);
                }
            }
        }
        $written = [];
        foreach (SealedRows::VALUES as $table => $columns) {
            foreach (array_keys($columns) as $column) {
                $written[] = sprintf('%s.%s', $table, $column);
            }
        }

        // When
        sort($sealed);
        sort($written);

        // Then
        static::assertSame($sealed, $written, 'a column sealed with no value written into it is a column no dump is searched for.');
    }

    /**
     * The other half of what makes the criterion mean something: the search is only worth what the fixture
     * wrote. A row that failed to save leaves the dump with nothing of that family in it, and a search that
     * finds nothing in an empty table is green for the worst reason there is.
     */
    #[Test]
    public function theFixtureLeavesARowInEverySealedTable(): void
    {
        // Given
        self::rows();

        // When
        $counts = [];
        foreach (array_keys(SealedRows::VALUES) as $table) {
            $count = self::connection()->fetchOne(sprintf('SELECT COUNT(*) FROM %s', $table));
            $counts[$table] = is_numeric($count) ? (int) $count : 0;
        }

        // Then
        static::assertSame(
            [],
            array_keys(array_filter($counts, static fn (int $rows): bool => $rows === 0)),
            'a family with no row is a family the dump is searched for in vain.',
        );
    }

    /**
     * A sealed column holds bytes indistinguishable from random, so a short value turns up in one by chance
     * and the run fails for nothing. The floor is what keeps a red run meaning a leak.
     */
    #[Test]
    public function noValueSearchedIsShortEnoughToTurnUpByChance(): void
    {
        // Given
        $tooShort = array_filter(
            SealedRows::searchable(),
            static fn (string $value): bool => strlen($value) < SealedRows::SHORTEST_VALUE,
        );

        // When / Then
        static::assertSame(
            [],
            array_values($tooShort),
            sprintf(
                'a value shorter than %d bytes is found in a ciphertext by chance rather than by leaking.',
                SealedRows::SHORTEST_VALUE,
            ),
        );
    }

    /**
     * The proof that the search is not vacuous: a value in a column no type seals is found, and the finding
     * names the column it sits in.
     */
    #[Test]
    public function aValueInAColumnNoTypeSealsIsFoundAndItsColumnNamed(): void
    {
        // Given
        $inTheClear = 'the-subject-no-type-seals';
        self::user('ada-the-second', $inTheClear);

        // When
        $findings = self::dump()->findings(self::connection(), [$inTheClear]);

        // Then
        static::assertNotSame([], $findings, 'the search found nothing where the value is in the clear, so it would find nothing anywhere.');
        foreach ($findings as $finding) {
            static::assertStringContainsString('beffroi_user.subject', $finding);
        }
    }

    /**
     * A value inside a document is escaped before it is stored, so a search for its bytes alone passes on a
     * column it should have failed.
     */
    #[Test]
    public function aValueEscapedAsJsonIsFoundToo(): void
    {
        // Given
        $value = 'https://ada.example.org/profile';
        $path = self::scratchFile((string) json_encode($value));

        // When
        $findings = SearchedDump::of($path)->findings(self::connection(), [$value]);
        unlink($path);

        // Then
        static::assertCount(1, $findings);
        static::assertStringContainsString('escaped as JSON', $findings[0]);
    }

    /**
     * A dump is the file and whatever the engine has not folded back into it yet.
     */
    #[Test]
    public function theSearchCoversTheDatabaseItself(): void
    {
        // Given
        self::rows();

        // When
        $dump = self::dump();

        // Then
        static::assertContains('the database', $dump->searched());
        static::assertGreaterThan(0, $dump->bytes());
    }

    private static function rows(): void
    {
        new SealedRows(self::getContainer(), self::tenant(), self::now())->all(self::client());
    }

    private static function dump(): SearchedDump
    {
        $database = static::getContainer()->getParameter('beffroi_test.database');
        if (! is_string($database)) {
            static::fail('The database of the test kernel is not a file.');
        }

        return SearchedDump::of($database);
    }

    private static function scratchFile(string $contents): string
    {
        $directory = static::getContainer()->getParameter('kernel.cache_dir');
        if (! is_string($directory)) {
            static::fail('The cache directory of the test kernel is not a path.');
        }
        $path = sprintf('%s/dump-%s', $directory, bin2hex(random_bytes(8)));
        file_put_contents($path, 'before' . $contents . 'after');

        return $path;
    }

    private static function connection(): Connection
    {
        return self::entityManager()->getConnection();
    }
}
