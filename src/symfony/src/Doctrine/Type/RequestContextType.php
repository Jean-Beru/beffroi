<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Type;

use Beffroi\Core\Domain\Session\RequestContext;

/**
 * Where a request came from and with what (architecture §3.5), as one JSON document and one column.
 *
 * **One column and not five**, which is what lets the column seal. A sealed column is a Doctrine type
 * decorating a type, and the family a type seals under is the table it belongs to (decisions 0011 and
 * 0018); a context held as an embeddable fixes the type of each of its fields once for the whole model, so
 * the same field could not carry the type of each of the three tables that hold a context. Nothing is lost:
 * the object is `final readonly` and `withLocation()` and `withDevice()` return a new one, so no write ever
 * touched a single field, and nothing anywhere reads a column of a context on its own.
 *
 * What the document holds, the two enrichments nested in it and the format of the moment, is the
 * provenance's own (`RequestContext::toDocument()`).
 *
 * @extends JsonObjectType<RequestContext>
 */
final class RequestContextType extends JsonObjectType
{
    public const string NAME = 'beffroi_request_context';

    protected function encode(object $value): array
    {
        return $value->toDocument();
    }

    protected function decode(array $data): object
    {
        return RequestContext::fromDocument($data);
    }

    protected function expects(): string
    {
        return RequestContext::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }
}
