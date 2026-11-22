<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Support;

use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Loader;

/**
 * Section 6.1 step 7
 */
final class Loaded
{
    public static function document(string $bytes): Document
    {
        return new Loader(Stack::idAttributes())->load($bytes);
    }

    public static function fixture(string $path): Document
    {
        return self::document(Fixtures::bytes($path));
    }
}
