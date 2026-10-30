<?php

declare(strict_types=1);

namespace App\Tests\Image;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function rtrim;
use function str_contains;
use function str_starts_with;
use function substr;

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
 * looked for after the last line that lets a path back in, so that no later line admits it again
 * (BuildContext).
 */
final class WorkingCopyStaysOutOfTheImageTest extends TestCase
{
    #[Test]
    #[DataProvider('provideWhatTheRepositoryIgnores')]
    public function theBuildLeavesOutWhatTheRepositoryIgnores(string $pattern): void
    {
        // Given
        $excluded = BuildContext::ofThisApplication()->exclusions;

        // When / Then
        static::assertContains($pattern, $excluded);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWhatTheRepositoryIgnores(): iterable
    {
        foreach (ApplicationFiles::linesOf('.gitignore') as $ignored) {
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
            return ApplicationFiles::FROM_THE_ROOT . substr($path, 1);
        }

        return ApplicationFiles::FROM_THE_ROOT . (str_contains($path, '/') ? $path : '**/' . $path);
    }
}
