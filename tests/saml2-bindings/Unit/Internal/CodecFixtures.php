<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit\Internal;

use function dirname;
use function file_get_contents;
use function is_string;
use LogicException;
use function sprintf;

/**
 * Section 9.7
 */
trait CodecFixtures
{
    private static function fixture(string $path): string
    {
        $bytes = file_get_contents(dirname(__DIR__, 2) . '/Fixture/' . $path);
        if (! is_string($bytes)) {
            throw new LogicException(sprintf('The fixture %s cannot be read.', $path));
        }

        return $bytes;
    }
}
