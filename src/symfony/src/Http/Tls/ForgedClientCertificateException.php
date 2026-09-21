<?php

declare(strict_types=1);

namespace Heidi\Bundle\Http\Tls;

use RuntimeException;
use function sprintf;

/**
 * A request asked to be read as if it had presented a client certificate, by carrying one in a header.
 * Nothing in front of this application sets such a header, so the only thing that can have set it is
 * whoever sent the request: it is refused out loud rather than ignored (decision 0006).
 */
final class ForgedClientCertificateException extends RuntimeException
{
    public static function carriedBy(string $header): self
    {
        return new self(sprintf('The request carries a client certificate in the "%s" header, which nothing in front of this application sets.', $header));
    }
}
