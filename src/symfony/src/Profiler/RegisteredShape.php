<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Profiler;

use Beffroi\Oidc\Domain\Client\ResponseFormat;
use function sprintf;

/**
 * How the panel says the shape a client registered for one of the documents the provider hands it
 * (OIDC Registration §2, JARM §3): signed, then encrypted, in the order the document is written in.
 * Written once, for the client that registered it and for the document that is issued in it.
 */
final readonly class RegisteredShape
{
    public static function of(ResponseFormat $format): string
    {
        $shape = $format->isSigned ? sprintf('signed with %s', $format->signature?->name() ?? 'the algorithm of the provider') : 'unsigned';
        if ($format->encryption !== null) {
            $shape .= sprintf(', encrypted with %s and %s', $format->encryption->algorithm->name(), $format->encryption->method->name());
        }

        return $shape;
    }
}
