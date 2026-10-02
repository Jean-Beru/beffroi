<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Fido\Conformance;

use InvalidArgumentException;

/**
 * A request of the FIDO2 server API the endpoint cannot read: answered with the message, as "failed".
 */
final class ServerRequestException extends InvalidArgumentException
{
}
