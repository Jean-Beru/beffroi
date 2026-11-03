<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Type;

use Beffroi\Oidc\Domain\Authorization\ClaimsRequest;

/**
 * The "claims" parameter (OIDC Core §5.5) in one JSON column, in the form of the wire, which is the
 * document the request writes itself as (`ClaimsRequest::toDocument()`).
 *
 * @extends JsonbObjectType<ClaimsRequest>
 */
final class ClaimsRequestType extends JsonbObjectType
{
    public const string NAME = 'beffroi_claims_request';

    protected function encode(object $value): array
    {
        return $value->toDocument();
    }

    protected function decode(array $data): object
    {
        return ClaimsRequest::fromDocument($data);
    }

    protected function expects(): string
    {
        return ClaimsRequest::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }
}
