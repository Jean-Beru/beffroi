<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;

/**
 * A value object stored as a JSONB document on PostgreSQL, and as the platform declares a JSON document
 * wherever it has no JSONB.
 *
 * The type declares the column, as DBAL's own `JsonbType` does by asking the platform for
 * `getJsonbTypeDeclarationSQL()`, so a mapping names the type and asks the platform for nothing: the "jsonb"
 * column platform option that would say it there is deprecated since doctrine/dbal 4.3.0
 * (doctrine/dbal#6939). Everything else is `JsonObjectType`'s.
 *
 * @template T of object
 *
 * @extends JsonObjectType<T>
 */
abstract class JsonbObjectType extends JsonObjectType
{
    public function getSQLDeclaration(array $column, AbstractPlatform $platform): string
    {
        return $platform->getJsonbTypeDeclarationSQL($column);
    }
}
