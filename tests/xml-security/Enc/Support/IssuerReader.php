<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Support;

use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Text;
use Beffroi\Xml\Enc\PlaintextReaderInterface;
use Beffroi\Xml\Tests\Core\Support\Stack;

/**
 * Section 5.2
 *
 * @implements PlaintextReaderInterface<string>
 */
final readonly class IssuerReader implements PlaintextReaderInterface
{
    public function read(Document $plaintext): string
    {
        return Text::of(Children::one($plaintext->root(), new Name(Stack::SAML_ASSERTION, 'Issuer')));
    }
}
