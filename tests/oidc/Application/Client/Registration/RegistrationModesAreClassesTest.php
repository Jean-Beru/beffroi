<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Client\Registration;

use function dirname;
use function file_get_contents;
use Heidi\Oidc\Application\Client\Registration\InitialAccessTokenAuthorization;
use function implode;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;
use function str_contains;
use function str_ends_with;
use function str_replace;
use function strtr;

/**
 * Decision 0009: a mode of registration is a class added and a line of wiring, so the name of a mode is
 * written in the class that is that mode and nowhere else. Anything that compared a mode to a literal
 * would be a place to edit when #338 and #347 add theirs, which is the shape this project refuses.
 *
 * The wiring of a deployment names a mode, of course: that is what a policy is. What is checked here is
 * the source of the two packages, where nothing but the class itself may spell it.
 */
final class RegistrationModesAreClassesTest extends TestCase
{
    #[Test]
    public function theNameOfAModeIsSpelledInTheClassThatIsThatModeAlone(): void
    {
        // Given
        $mode = InitialAccessTokenAuthorization::MODE;
        $itself = str_replace('\\', '/', strtr(InitialAccessTokenAuthorization::class, [
            'Heidi\Oidc\\' => 'src/oidc/src/',
            'Heidi\Bundle\\' => 'src/symfony/src/',
        ])) . '.php';

        // When
        $spelling = [];
        foreach (self::sources() as $path) {
            if (! str_ends_with($path, $itself) && str_contains(self::contents($path), "'" . $mode . "'")) {
                $spelling[] = $path;
            }
        }

        // Then
        static::assertSame([], $spelling, 'The name of a registration mode is spelled in ' . implode(', ', $spelling));
    }

    /**
     * @return list<string>
     */
    private static function sources(): array
    {
        $root = dirname(__DIR__, 4);
        $paths = [];
        foreach (['/../src/oidc/src', '/../src/symfony/src'] as $directory) {
            /** @var iterable<SplFileInfo> $files */
            $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root . $directory));
            foreach ($files as $file) {
                $path = $file->getPathname();
                if (str_ends_with($path, '.php')) {
                    $paths[] = $path;
                }
            }
        }

        return $paths;
    }

    private static function contents(string $path): string
    {
        $contents = file_get_contents($path);

        return $contents === false ? '' : $contents;
    }
}
