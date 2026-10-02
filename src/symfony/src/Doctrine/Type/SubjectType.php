<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Type;

use Beffroi\Core\Domain\Identity\Subject;

/**
 * The "sub" of a user (OIDC Core §2), stored as is.
 *
 * @extends StringObjectType<Subject>
 */
final class SubjectType extends StringObjectType
{
    public const string NAME = 'beffroi_subject';

    protected function encode(object $value): string
    {
        return $value->value;
    }

    protected function decode(string $value): object
    {
        return new Subject($value);
    }

    protected function expects(): string
    {
        return Subject::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }
}
