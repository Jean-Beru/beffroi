<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Type;

use function array_filter;
use Beffroi\Core\Domain\Identity\Profile;
use Doctrine\DBAL\Types\Exception\ValueNotConvertible;
use Error;
use function get_object_vars;
use function is_string;

/**
 * What a person says of themselves, the thirteen claims of OIDC Core §5.1 the profile of a user holds, as
 * one document.
 *
 * It names no claim and no field. The document is the public properties of the object, written by their own
 * names and read back as named arguments of its constructor, so a claim added to that object is a claim
 * this type carries without a line: the names of §5.1 are matched with the fields that hold them in
 * `Profile::describedWith()`, and a fourth place to be wrong is not opened here. A key the constructor does
 * not answer to, or a value that is not a string, is a conversion error and never a guess.
 *
 * What a profile holds nothing of is absent from the document rather than written null, which is what the
 * constructor already answers for.
 *
 * @extends JsonObjectType<Profile>
 */
final class ProfileType extends JsonObjectType
{
    public const string NAME = 'beffroi_profile';

    protected function encode(object $value): array
    {
        return array_filter(get_object_vars($value), static fn (mixed $claim): bool => $claim !== null);
    }

    protected function decode(array $data): object
    {
        $named = [];
        foreach ($data as $name => $claim) {
            if (! is_string($name) || ! is_string($claim)) {
                throw ValueNotConvertible::new(
                    $data,
                    self::NAME,
                    'A profile is a document of claims named by the fields that hold them, each a string.',
                );
            }
            $named[$name] = $claim;
        }

        try {
            return new Profile(...$named);
        } catch (Error $error) {
            throw ValueNotConvertible::new($data, self::NAME, $error->getMessage(), $error);
        }
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
