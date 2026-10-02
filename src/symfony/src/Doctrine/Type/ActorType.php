<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Type;

use Beffroi\Oidc\Domain\Exchange\Actor;

/**
 * Who holds an opaque access token on behalf of its subject, stored as the "act" of RFC 8693 §4.1 is written:
 * the members themselves, nested, so that the row says the same thing an "at+jwt" says of the same token and
 * the introspection of either renders one chain.
 *
 * @extends JsonObjectType<Actor>
 */
final class ActorType extends JsonObjectType
{
    public const string NAME = 'beffroi_actor';

    protected function encode(object $value): array
    {
        return $value->toClaim();
    }

    protected function decode(array $data): object
    {
        return Actor::fromClaim($data);
    }

    protected function expects(): string
    {
        return Actor::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }
}
