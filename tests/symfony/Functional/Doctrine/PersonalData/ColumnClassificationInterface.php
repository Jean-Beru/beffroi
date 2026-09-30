<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine\PersonalData;

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
     * @param string $column "table.column", as a finding names it
     * @param bool   $sealed whether the Doctrine type of the column seals what it stores
     */
    public function finding(string $column, bool $sealed): ?string;
}
