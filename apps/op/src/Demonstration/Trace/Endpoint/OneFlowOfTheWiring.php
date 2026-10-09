<?php

declare(strict_types=1);

namespace App\Demonstration\Trace\Endpoint;

use function count;
use Beffroi\Oidc\Domain\Client\GrantTypeName;

/**
 * The one flow of a wiring that reaches an endpoint only one kind of grant reaches: the device
 * authorization endpoint (RFC 8628 §3.1) and the backchannel authentication endpoint (CIBA Core §7)
 * each serve the grants of one capability, and a call to one of them belongs to that flow.
 *
 * A wiring that held two grants of the same capability could not say which of them a call belongs to,
 * and a hop the wiring cannot attribute is not drawn: the demonstration draws what it can read and
 * never what it guesses.
 *
 * @see \App\Demonstration\Trace\RecordedEndpointInterface::flowOf()
 */
final readonly class OneFlowOfTheWiring
{
    /**
     * @param list<GrantTypeName> $grantTypes those of the capability the endpoint serves
     */
    public static function of(array $grantTypes): ?GrantTypeName
    {
        return count($grantTypes) === 1 ? $grantTypes[0] : null;
    }
}
