<?php

declare(strict_types=1);

namespace Heidi\Bundle\Profiler;

use function explode;
use function str_contains;

/**
 * Which key management service the deployment opens its envelopes with, read from the scheme of the DSN
 * the bundle is configured with and from nothing else: the rest of a DSN may carry a credential or a key
 * identifier, and a panel that printed it would publish it to whoever opens the profiler.
 */
final readonly class KmsBackend
{
    public function __construct(
        private string $dsn,
    ) {
    }

    public function name(): string
    {
        if (! str_contains($this->dsn, '://')) {
            return 'unnamed';
        }

        return explode('://', $this->dsn, 2)[0];
    }
}
