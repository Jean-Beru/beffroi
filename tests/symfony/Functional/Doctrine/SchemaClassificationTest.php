<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine;

use function count;
use function explode;
use Heidi\Bundle\Tests\Functional\Doctrine\PersonalData\BundleSchema;
use Heidi\Bundle\Tests\Functional\Doctrine\PersonalData\ClassifiedSchema;
use Heidi\Bundle\Tests\Functional\Doctrine\PersonalData\NoPersonalDatum;
use Heidi\Bundle\Tests\Functional\Doctrine\PersonalData\Owed;
use Heidi\Bundle\Tests\Functional\Doctrine\PersonalData\SchemaColumns;
use Heidi\Bundle\Tests\Functional\Doctrine\PersonalData\Sealed;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function preg_match;

/**
 * Decision 0011: "Toute colonne à venir qui porte une donnée personnelle, par construction : un test
 * énumère les colonnes du schéma et refuse une colonne qui n'est ni déclarée hors données personnelles,
 * ni d'un type chiffré. Une colonne nouvelle est classée ou le test est rouge."
 *
 * SchemaColumns is that classification and ClassifiedSchema is the walk. This holds the two against the
 * schema Doctrine builds, and shows on a schema of its own what each kind of line refuses.
 */
final class SchemaClassificationTest extends DatabaseTestCase
{
    /**
     * How many tables and columns the schema holds, written out so that a table added whole, or a column
     * added to one, is a figure to change here and a line to add there. All but one are described by a
     * mapping of the bundle; the last is the table of the data key store, which the listener of the ORM
     * bridge puts in the schema the ORM assembles (decisions 0011 and 0018).
     */
    private const int TABLES = 24;

    private const int COLUMNS = 301;

    #[Test]
    public function everyColumnOfEveryTableIsClassified(): void
    {
        // Given
        $schema = BundleSchema::columns(self::entityManager(), SchemaColumns::sealingTypes());

        // When / Then
        static::assertSame([], new ClassifiedSchema(SchemaColumns::all())->findings($schema));
    }

    #[Test]
    public function theClassificationCoversAsManyTablesAndColumnsAsTheMappingsDescribe(): void
    {
        // Given
        $classification = new ClassifiedSchema(SchemaColumns::all());

        // When / Then
        static::assertCount(self::TABLES, $classification->tables());
        static::assertSame(self::COLUMNS, $classification->columnCount());
    }

    #[Test]
    public function aColumnTheSchemaDeclaresAndNoListNamesIsRefused(): void
    {
        // Given
        $classification = new ClassifiedSchema([
            'heidi_user' => ['id' => new NoPersonalDatum(SchemaColumns::DRAWN_AT_RANDOM)],
        ]);

        // When
        $findings = $classification->findings([
            'heidi_user' => [
                'id' => false,
                'favourite_colour' => false,
            ],
        ]);

        // Then
        static::assertSame(
            [
                'heidi_user.favourite_colour is in the schema and in no list: declare it readable with the reason a dump of it gives nothing away, sealed, or owed to the issue that seals it.',
            ],
            $findings,
        );
    }

    /**
     * A table added whole is every one of its columns named nowhere, so it is refused column by column.
     */
    #[Test]
    public function aTableTheSchemaDeclaresAndNoListNamesIsRefused(): void
    {
        // Given
        $classification = new ClassifiedSchema([]);

        // When
        $findings = $classification->findings([
            'heidi_new_table' => [
                'id' => false,
                'tenant_id' => false,
            ],
        ]);

        // Then
        static::assertCount(2, $findings);
    }

    #[Test]
    public function aColumnOwedToAnIssueAndFoundSealedIsRefused(): void
    {
        // Given
        $classification = new ClassifiedSchema([
            'heidi_user' => ['email' => new Owed('heidi#402', 'the electronic address of a person')],
        ]);

        // When
        $findings = $classification->findings(['heidi_user' => ['email' => true]]);

        // Then
        static::assertSame(
            [
                'heidi_user.email is sealed and heidi#402 still owes it ("the electronic address of a person"): delete its line and declare it sealed.',
            ],
            $findings,
        );
    }

    #[Test]
    public function aColumnDeclaredSealedAndFoundInTheClearIsRefused(): void
    {
        // Given
        $classification = new ClassifiedSchema([
            'heidi_user' => ['email' => new Sealed('user')],
        ]);

        // When
        $findings = $classification->findings(['heidi_user' => ['email' => false]]);

        // Then
        static::assertSame(
            [
                'heidi_user.email is declared sealed under the "user" family and its Doctrine type does not seal it.',
            ],
            $findings,
        );
    }

    #[Test]
    public function aColumnDeclaredReadableAndFoundSealedIsRefused(): void
    {
        // Given
        $classification = new ClassifiedSchema([
            'heidi_user' => ['id' => new NoPersonalDatum(SchemaColumns::DRAWN_AT_RANDOM)],
        ]);

        // When
        $findings = $classification->findings(['heidi_user' => ['id' => true]]);

        // Then
        static::assertSame(
            [
                'heidi_user.id is sealed, and is declared readable ("' . SchemaColumns::DRAWN_AT_RANDOM . '"): move its line to the sealed list.',
            ],
            $findings,
        );
    }

    #[Test]
    public function aLineWhoseColumnTheSchemaNoLongerDeclaresIsRefused(): void
    {
        // Given
        $classification = new ClassifiedSchema([
            'heidi_user' => [
                'id' => new NoPersonalDatum(SchemaColumns::DRAWN_AT_RANDOM),
                'pager_number' => new Owed('heidi#402', 'the pager number of a person'),
            ],
        ]);

        // When
        $findings = $classification->findings(['heidi_user' => ['id' => false]]);

        // Then
        static::assertSame(
            [
                'heidi_user.pager_number is classified and the schema does not declare it: delete its line.',
            ],
            $findings,
        );
    }

    /**
     * Decision 0011 gives the reasons a column stays readable, and a reason is read by a person: it is a
     * sentence, and not the name of a category.
     */
    #[Test]
    public function theReasonOfEveryReadableColumnIsASentence(): void
    {
        // When / Then
        foreach (SchemaColumns::all() as $table => $columns) {
            foreach ($columns as $column => $line) {
                if (! $line instanceof NoPersonalDatum) {
                    continue;
                }
                static::assertGreaterThanOrEqual(5, count(explode(' ', $line->reason)), $table . '.' . $column);
            }
        }
    }

    /**
     * The four reasons decision 0011 writes down, each of them the whole truth of at least one column of
     * the schema as it stands.
     */
    #[Test]
    #[DataProvider('provideReasonsOfDecision0011')]
    public function eachReasonOfDecision0011ClassifiesAColumn(string $reason): void
    {
        // When
        $columns = [];
        foreach (SchemaColumns::all() as $table => $lines) {
            foreach ($lines as $column => $line) {
                if ($line instanceof NoPersonalDatum && $line->reason === $reason) {
                    $columns[] = $table . '.' . $column;
                }
            }
        }

        // Then
        static::assertNotSame([], $columns, $reason);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideReasonsOfDecision0011(): iterable
    {
        yield 'hashed' => [SchemaColumns::HASHED];

        yield 'random' => [SchemaColumns::DRAWN_AT_RANDOM];

        yield 'public by construction' => [SchemaColumns::PUBLIC_BY_CONSTRUCTION];

        yield 'names no person' => [SchemaColumns::NAMES_NO_PERSON];
    }

    /**
     * The "known" list of CONFORMANCE_PLANS carries the issue that closes each gap, and so does this
     * one: an owed column with no issue is a column nobody has undertaken to seal.
     */
    #[Test]
    public function everyOwedColumnNamesTheIssueThatSealsIt(): void
    {
        // When / Then
        foreach (SchemaColumns::all() as $table => $columns) {
            foreach ($columns as $column => $line) {
                if (! $line instanceof Owed) {
                    continue;
                }
                static::assertSame(1, preg_match('/^heidi#\d+$/', $line->issue), $table . '.' . $column);
                static::assertGreaterThanOrEqual(5, count(explode(' ', $line->reason)), $table . '.' . $column);
            }
        }
    }
}
