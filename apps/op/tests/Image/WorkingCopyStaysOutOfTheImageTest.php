<?php

declare(strict_types=1);

namespace App\Tests\Image;

use function array_filter;
use function array_key_last;
use function array_map;
use function array_slice;
use function array_values;
use function dirname;
use function explode;
use function file_get_contents;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function rtrim;
use function sprintf;
use function str_contains;
use function str_starts_with;
use function substr;
use function trim;

/**
 * Issue #832: the production image is built from the root of the monorepo (compose.yaml), and what a working
 * copy holds beside the repository stays out of it. "castor provision" writes the DSN of the KMS (the key
 * itself under the sodium backend, a token under Vault), the secrets of the clients and the password of the
 * development user into .env.local, and "composer dump-env prod" compiles into the image whatever .env.local
 * the build was given.
 *
 * What a working copy holds beside the repository is what the .gitignore of this application names, and
 * Docker reads no .gitignore: Dockerfile.dockerignore names those paths a second time, and this holds the two
 * lists together. A path the .gitignore gains is a path the build leaves out, or this fails. Each one is
 * looked for after the last line that lets a path back in, so that no later line admits it again.
 *
 * No daemon is asked here: which file BuildKit reads, and what it then sends, is what building the image
 * shows.
 */
final class WorkingCopyStaysOutOfTheImageTest extends TestCase
{
    private const string APPLICATION = 'apps/op/';

    #[Test]
    #[DataProvider('provideWhatTheRepositoryIgnores')]
    public function theBuildLeavesOutWhatTheRepositoryIgnores(string $pattern): void
    {
        // Given
        $excluded = self::excludedAfterTheLastInclusion();

        // When / Then
        static::assertContains($pattern, $excluded);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWhatTheRepositoryIgnores(): iterable
    {
        foreach (self::patternsOf('.gitignore') as $ignored) {
            if (! str_starts_with($ignored, '!')) {
                yield $ignored => [self::fromTheRootOfTheMonorepo($ignored)];
            }
        }
    }

    /**
     * gitignore(5): a pattern with a slash at its beginning or in its middle is read from the directory of
     * the .gitignore, and one without matches at any depth below it. The ignore file of the Dockerfile reads
     * its paths from the root of the monorepo, where Docker strips the slash that ends a pattern.
     */
    private static function fromTheRootOfTheMonorepo(string $ignored): string
    {
        $path = rtrim($ignored, '/');
        if (str_starts_with($path, '/')) {
            return self::APPLICATION . substr($path, 1);
        }

        return self::APPLICATION . (str_contains($path, '/') ? $path : '**/' . $path);
    }

    /**
     * @return list<string>
     */
    private static function excludedAfterTheLastInclusion(): array
    {
        $patterns = self::patternsOf('Dockerfile.dockerignore');
        $inclusions = array_filter($patterns, static fn (string $pattern): bool => str_starts_with($pattern, '!'));
        $lastInclusion = array_key_last($inclusions) ?? -1;

        return array_map(
            static fn (string $pattern): string => rtrim($pattern, '/'),
            array_slice($patterns, $lastInclusion + 1),
        );
    }

    /**
     * @return list<string> the lines of a file of this application that are neither empty nor a comment
     */
    private static function patternsOf(string $file): array
    {
        $content = file_get_contents(dirname(__DIR__, 2) . '/' . $file);
        if ($content === false) {
            self::fail(sprintf('The file "%s" of the application cannot be read.', $file));
        }

        return array_values(array_filter(
            array_map(trim(...), explode("\n", $content)),
            static fn (string $line): bool => $line !== '' && ! str_starts_with($line, '#'),
        ));
    }
}
