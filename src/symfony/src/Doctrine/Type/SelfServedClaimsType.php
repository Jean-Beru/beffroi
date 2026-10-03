<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Type;

use Beffroi\Core\Domain\Tenant\SelfServedClaims;
use Doctrine\DBAL\Types\Exception\ValueNotConvertible;
use function array_values;
use function is_string;

/**
 * What a person may change of themselves in a tenant (issue #452), as a JSON array of claim names: a list
 * and not an object, because what it holds is a set of names in the order they were declared and nothing
 * is keyed by them.
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
        return $value->names;
    }

    protected function decode(array $data): object
    {
        $names = [];
        foreach (array_values($data) as $name) {
            if (! is_string($name)) {
                throw ValueNotConvertible::new($data, self::NAME, 'The claims a person may change of themselves are names.');
            }
            $names[] = $name;
        }

        return new SelfServedClaims($names);
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
