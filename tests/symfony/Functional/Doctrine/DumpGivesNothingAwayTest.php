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

final class DumpGivesNothingAwayTest extends DatabaseTestCase
{
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
