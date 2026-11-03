<?php

declare(strict_types=1);

namespace App\Doctrine\Type;

use Beffroi\Core\Domain\Tenant\SelfServedClaims;

/**
 * What a person may change of themselves in a tenant (issue #452), as the JSON array of claim names the
 * value writes itself as (`SelfServedClaims::toDocument()`).
 *
 * A tenant that lets a person change nothing is an empty array, which is the default of the column, so a
 * row written before the column existed says what it would have said.
 *
 * @extends JsonObjectType<SelfServedClaims>
 */
final class SelfServedClaimsType extends JsonObjectType
{
    public const string NAME = 'beffroi_self_served_claims';

    protected function encode(object $value): array
    {
        return $value->toDocument();
    }

    protected function decode(array $data): object
    {
        return SelfServedClaims::fromDocument($data);
    }

    protected function expects(): string
    {
        return SelfServedClaims::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }
}
