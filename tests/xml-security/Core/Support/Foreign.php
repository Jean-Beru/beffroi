<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Support;

use Dom\XMLDocument;
use function libxml_clear_errors;
use const LIBXML_NONET;
use function libxml_use_internal_errors;

/**
 * I-1, I-3, I-4
 */
final class Foreign
{
    public static function parse(string $bytes): XMLDocument
    {
        $previous = libxml_use_internal_errors(true);
        try {
            return XMLDocument::createFromString($bytes, LIBXML_NONET);
        } finally {
            libxml_clear_errors();
            libxml_use_internal_errors($previous);
        }
    }
}
