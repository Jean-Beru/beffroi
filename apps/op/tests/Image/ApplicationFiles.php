<?php

declare(strict_types=1);

namespace App\Tests\Image;

use function array_filter;
use function array_map;
use function array_values;
use function dirname;
use function explode;
use function file_get_contents;
use PHPUnit\Framework\Assert;
use function sprintf;
use function str_starts_with;
use function trim;

/**
 * The files of this application as the tests of its image read them: by their path in the application, and by
 * the path the build of the image names them by, from the root of the monorepo it is built from (compose.yaml).
 */
final class ApplicationFiles
{
    public const string FROM_THE_ROOT = 'apps/op/';

    public static function path(string $file): string
    {
        return dirname(__DIR__, 2) . '/' . $file;
    }

    /**
     * @return list<string> the lines of a file of this application that are neither empty nor a comment: the
     *                      patterns of an ignore file, the variables of an environment file
     */
    public static function linesOf(string $file): array
    {
        $content = file_get_contents(self::path($file));
        if ($content === false) {
            Assert::fail(sprintf('The file "%s" of the application cannot be read.', $file));
        }

        return array_values(array_filter(
            array_map(trim(...), explode("\n", $content)),
            static fn (string $line): bool => $line !== '' && ! str_starts_with($line, '#'),
        ));
    }
}
