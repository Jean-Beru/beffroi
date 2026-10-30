<?php

declare(strict_types=1);

namespace App\Tests\Image;

use function array_filter;
use function array_key_last;
use function array_map;
use function array_slice;
use function explode;
use function fnmatch;
use const FNM_PATHNAME;
use function rtrim;
use function str_starts_with;
use function strpbrk;
use function substr;

/**
 * What the build of the image is given of this application (issues #832 and #922). apps/op/Dockerfile.dockerignore,
 * which BuildKit reads for apps/op/Dockerfile in place of a .dockerignore at the root of the monorepo, lets "src/"
 * and "apps/op/" in after "*", then names what of them stays out, every path written from that root.
 *
 * A path of the application is left out when a pattern after the last line that lets a path back in names it: the
 * path itself or a directory above it, a path the pattern matches, or, for a pattern under "**", a name the path
 * carries at any depth. Docker strips the slash that ends a pattern, and so does this.
 *
 * No daemon is asked here: which file BuildKit reads, and what it then sends, is what building the image shows.
 */
final readonly class BuildContext
{
    /**
     * @param list<string> $exclusions the patterns after the last one that lets a path back in
     */
    private function __construct(
        public array $exclusions,
    ) {
    }

    public static function ofThisApplication(): self
    {
        $patterns = ApplicationFiles::linesOf('Dockerfile.dockerignore');
        $inclusions = array_filter($patterns, static fn (string $pattern): bool => str_starts_with($pattern, '!'));
        $lastInclusion = array_key_last($inclusions) ?? -1;

        return new self(array_map(
            static fn (string $pattern): string => rtrim($pattern, '/'),
            array_slice($patterns, $lastInclusion + 1),
        ));
    }

    /**
     * @param string $file the path of a file or of a directory in the application
     */
    public function leavesOut(string $file): bool
    {
        $path = ApplicationFiles::FROM_THE_ROOT . $file;
        foreach ($this->exclusions as $pattern) {
            if (str_starts_with($pattern, '**/')) {
                foreach (explode('/', $path) as $name) {
                    if (fnmatch(substr($pattern, 3), $name)) {
                        return true;
                    }
                }

                continue;
            }
            if ($path === $pattern || str_starts_with($path, $pattern . '/')) {
                return true;
            }
            if (strpbrk($pattern, '*?[') !== false && fnmatch($pattern, $path, FNM_PATHNAME)) {
                return true;
            }
        }

        return false;
    }
}
