<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Dsig\Support;

use Beffroi\Xml\Dsig\SignatureAlgorithm;
use Beffroi\Xml\Dsig\SigningKeyInterface;

/**
 * Section 5.2
 */
final class RecordingKey implements SigningKeyInterface
{
    public ?string $bytes = null;

    public ?SignatureAlgorithm $algorithm = null;

    public function __construct(
        private readonly string $answer,
    ) {
    }

    public function sign(string $bytes, SignatureAlgorithm $algorithm): string
    {
        $this->bytes = $bytes;
        $this->algorithm = $algorithm;

        return $this->answer;
    }
}
