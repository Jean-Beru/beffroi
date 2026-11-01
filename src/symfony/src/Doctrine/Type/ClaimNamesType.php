<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Type;

use Beffroi\Oidc\Domain\Claims\ClaimNames;

/**
 * Claims by their names (OIDC Core §5.1), as the JSON array the set writes itself as
 * (`ClaimNames::toDocument()`).
 *
 * A set that holds no name is an empty array, which is the default of the column, so a row written before
 * the column existed says what it would have said.
 *
 * @extends JsonObjectType<ClaimNames>
 */
final class ClaimNamesType extends JsonObjectType
{
    public const string NAME = 'beffroi_claim_names';

    protected function encode(object $value): array
    {
        return $value->toDocument();
    }

    protected function decode(array $data): object
    {
        return ClaimNames::fromDocument($data);
    }

    protected function expects(): string
    {
        return ClaimNames::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }
}
