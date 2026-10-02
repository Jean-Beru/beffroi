<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Type;

use Beffroi\Oidc\Domain\Claims\SectorIdentifier;

/**
 * The sector a pairwise identifier belongs to (OIDC Core §8.1), stored as the host it is.
 *
 * @extends StringObjectType<SectorIdentifier>
 */
final class SectorIdentifierType extends StringObjectType
{
    public const string NAME = 'beffroi_sector_identifier';

    protected function encode(object $value): string
    {
        return $value->host;
    }

    protected function decode(string $value): object
    {
        return new SectorIdentifier($value);
    }

    protected function expects(): string
    {
        return SectorIdentifier::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }
}
