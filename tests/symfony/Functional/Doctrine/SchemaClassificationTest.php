<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Doctrine;

use function array_keys;
use function count;
use function explode;
use Beffroi\Bundle\Doctrine\PersonalData\EncryptedColumnTypes;
use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\BundleSchema;
use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\ClassifiedSchema;
use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\NoPersonalDatum;
use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\Owed;
use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\SchemaColumns;
use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\Sealed;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function preg_match;
use function sort;

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
    private const int TABLES = 28;

    private const int COLUMNS = 320;

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
            'beffroi_user' => ['id' => new NoPersonalDatum(SchemaColumns::DRAWN_AT_RANDOM)],
        ]);

        // When
        $findings = $classification->findings([
            'beffroi_user' => [
                'id' => null,
                'favourite_colour' => null,
            ],
        ]);

        // Then
        static::assertSame(
            [
                'beffroi_user.favourite_colour is in the schema and in no list: declare it readable with the reason a dump of it gives nothing away, sealed, or owed to the issue that seals it.',
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
            'beffroi_new_table' => [
                'id' => null,
                'tenant_id' => null,
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
            'beffroi_user' => ['email' => new Owed('beffroi#402', 'the electronic address of a person')],
        ]);

        // When
        $findings = $classification->findings(['beffroi_user' => ['email' => 'beffroi_encrypted_user_email_address']]);

        // Then
        static::assertSame(
            [
                'beffroi_user.email is sealed and beffroi#402 still owes it ("the electronic address of a person"): delete its line and declare it sealed.',
            ],
            $findings,
        );
    }

    #[Test]
    public function aColumnDeclaredSealedAndFoundInTheClearIsRefused(): void
    {
        // Given
        $classification = new ClassifiedSchema([
            'beffroi_user' => ['email' => new Sealed('user')],
        ]);

        // When
        $findings = $classification->findings(['beffroi_user' => ['email' => null]]);

        // Then
        static::assertSame(
            [
                'beffroi_user.email is declared sealed under the "user" family and its Doctrine type does not seal it.',
            ],
            $findings,
        );
    }

    /**
     * A column seals under its own table, the family being the name of the table without the prefix of
     * the bundle: a column sealed under another family is a value written into the scope of a table that
     * is not its own, which no destruction of its tenant's keys for that table would reach.
     */
    #[Test]
    public function aColumnDeclaredSealedUnderAnotherTableIsRefused(): void
    {
        // Given
        $classification = new ClassifiedSchema([
            'beffroi_interaction' => ['login_hint' => new Sealed('user')],
        ]);

        // When
        $findings = $classification->findings(['beffroi_interaction' => ['login_hint' => 'beffroi_encrypted_user_text']]);

        // Then
        static::assertSame(
            [
                'beffroi_interaction.login_hint is declared sealed under the "user" family, and a column seals under its own table, so under "interaction".',
            ],
            $findings,
        );
    }

    /**
     * And the shape of the mapping that produces it without showing it: an embeddable fixes the type of
     * each of its fields once for the whole model, so a second entity embedding an object whose field
     * seals lands that field's column, with that type, on a table of another family.
     */
    #[Test]
    public function aColumnCarryingTheSealingTypeOfAnotherFamilyIsRefused(): void
    {
        // Given
        $classification = new ClassifiedSchema([
            'beffroi_consent' => ['login_hint' => new Sealed('consent')],
        ]);

        // When
        $findings = $classification->findings(['beffroi_consent' => ['login_hint' => 'beffroi_encrypted_interaction_text']]);

        // Then
        static::assertSame(
            [
                'beffroi_consent.login_hint is declared sealed under the "consent" family and carries "beffroi_encrypted_interaction_text", which seals under another: a column of an embeddable several entities embed cannot carry the type of one of their tables.',
            ],
            $findings,
        );
    }

    #[Test]
    public function aColumnDeclaredReadableAndFoundSealedIsRefused(): void
    {
        // Given
        $classification = new ClassifiedSchema([
            'beffroi_user' => ['id' => new NoPersonalDatum(SchemaColumns::DRAWN_AT_RANDOM)],
        ]);

        // When
        $findings = $classification->findings(['beffroi_user' => ['id' => 'beffroi_encrypted_user_string']]);

        // Then
        static::assertSame(
            [
                'beffroi_user.id is sealed, and is declared readable ("' . SchemaColumns::DRAWN_AT_RANDOM . '"): move its line to the sealed list.',
            ],
            $findings,
        );
    }

    #[Test]
    public function aLineWhoseColumnTheSchemaNoLongerDeclaresIsRefused(): void
    {
        // Given
        $classification = new ClassifiedSchema([
            'beffroi_user' => [
                'id' => new NoPersonalDatum(SchemaColumns::DRAWN_AT_RANDOM),
                'pager_number' => new Owed('beffroi#402', 'the pager number of a person'),
            ],
        ]);

        // When
        $findings = $classification->findings(['beffroi_user' => ['id' => null]]);

        // Then
        static::assertSame(
            [
                'beffroi_user.pager_number is classified and the schema does not declare it: delete its line.',
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
     * Every family the bundle declares seals at least one column of the schema. A family is a scope, and a
     * scope is a data key per tenant: one that no column seals under is a key minted for nothing, or a
     * declaration left behind by a column that moved. The count is read from the declaration and the
     * families from the classification, so neither can be the only one to know.
     */
    #[Test]
    public function everyFamilyTheBundleDeclaresSealsAColumn(): void
    {
        // Given
        $sealing = [];
        foreach (SchemaColumns::all() as $columns) {
            foreach ($columns as $line) {
                if ($line instanceof Sealed) {
                    $sealing[$line->family] = true;
                }
            }
        }

        // When
        $families = array_keys($sealing);
        sort($families);

        // Then
        $declared = EncryptedColumnTypes::families();
        sort($declared);
        static::assertSame(
            $declared,
            $families,
            'A family is declared and no column seals under it, or a column seals under a family nothing declares.',
        );
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
                static::assertSame(1, preg_match('/^beffroi#\d+$/', $line->issue), $table . '.' . $column);
                static::assertGreaterThanOrEqual(5, count(explode(' ', $line->reason)), $table . '.' . $column);
            }
        }
    }
}
