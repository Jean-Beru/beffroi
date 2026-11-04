<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Support;

use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Enc\CoveringSignatureInterface;

/**
 * Section 5.2, E-15
 */
final readonly class CoveringDocument implements CoveringSignatureInterface
{
    public function __construct(
        private Document $document,
    ) {
    }

    public function document(): Document
    {
        return $this->document;
    }
}
