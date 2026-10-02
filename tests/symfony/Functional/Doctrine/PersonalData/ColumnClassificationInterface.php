<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData;

/**
 * What one line of SchemaColumns says of one column, and what it has to say about the column the schema
 * actually declares. Decision 0011 asks for a test that "énumère les colonnes du schéma et refuse une
 * colonne qui n'est ni déclarée hors données personnelles, ni d'un type chiffré"; a line is that
 * declaration, and this is the one question the walk asks it.
 */
interface ColumnClassificationInterface
{
    /**
     * What the line and the column disagree on, or null when they agree.
     *
     * @param string      $table        the table the column is on, which is also the family a sealed column of it
     *                                  seals under
     * @param string      $column       the column, which a finding names as "table.column"
     * @param string|null $sealingType  the name of the encrypted type the mapping gives the column, or null when
     *                                  the type the mapping gives it does not seal
     */
    public function finding(string $table, string $column, ?string $sealingType): ?string;
}
