<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Type;

use Beffroi\Core\Domain\Identity\Profile;

/**
 * What a person says of themselves, the thirteen claims of OIDC Core §5.1 the profile of a user holds, as
 * one JSON column.
 *
 * It names no claim and no field, and neither does the document: the profile writes itself out of its own
 * properties and reads itself back through its constructor (`Profile::toDocument()`), so a claim added to
 * that object is a claim this column carries without a line here.
 *
 * @extends JsonObjectType<Profile>
 */
final class ProfileType extends JsonObjectType
{
    public const string NAME = 'beffroi_profile';

    protected function encode(object $value): array
    {
        return $value->toDocument();
    }

    protected function decode(array $data): object
    {
        return Profile::fromDocument($data);
    }

    protected function expects(): string
    {
        return Profile::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }
}
