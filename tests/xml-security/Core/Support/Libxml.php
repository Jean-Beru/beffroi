<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Support;

use Dom\XMLDocument;
use DOMException;
use function libxml_get_errors;
use const LIBXML_NONET;
use function libxml_use_internal_errors;
use LibXMLError;

/**
 * I-3
 */
final class Libxml
{
    public static function fillBuffer(): void
    {
        libxml_use_internal_errors(true);
        try {
            XMLDocument::createFromString('<unclosed>', LIBXML_NONET);
        } catch (DOMException) {
            // The parse fails on purpose: its diagnostic is what fills the buffer.
        }
    }

    /**
     * @return list<LibXMLError>
     */
    public static function buffer(): array
    {
        return libxml_get_errors();
    }

    public static function mode(): bool
    {
        return libxml_use_internal_errors();
    }
}
