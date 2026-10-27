<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use function strlen;

/**
 * Bytes a third party may answer before the read stops: what a document of its kind has any reason to be, so that a
 * party that answers more holds no worker reading it and no memory keeping it.
 */
final readonly class ByteLimit
{
    public function __construct(
        public int $bytes,
    ) {
    }

    public function isExceededBy(string $body): bool
    {
        return strlen($body) > $this->bytes;
    }
}
