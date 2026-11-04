<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Support;

use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Enc\PlaintextReaderInterface;

/**
 * Section 5.2
 *
 * @implements PlaintextReaderInterface<Document>
 */
final readonly class LoadedDocument implements PlaintextReaderInterface
{
    public function read(Document $plaintext): Document
    {
        return $plaintext;
    }
}
