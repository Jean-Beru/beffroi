<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit;

use SensitiveParameter;
use function array_filter;
use function array_keys;
use function array_values;
use function dirname;
use function file_get_contents;
use function implode;
use function ksort;
use PhpToken;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;
use function sprintf;
use function str_contains;
use function str_starts_with;
use function strlen;
use function strtolower;
use function substr;
use function substr_count;
use const T_CONSTANT_ENCAPSED_STRING;
use const T_DOUBLE_COLON;
use const T_ENCAPSED_AND_WHITESPACE;
use const T_SPACESHIP;
use const T_STRING;

/**
 * Section 8, M-6, M-7, M-12, I-12
 */
final class SourceGuardTest extends TestCase
{
    /**
     * Section 8, M-12, I-12
     */
    #[Test]
    #[DataProvider('provideBannedTokens')]
    public function itNeverWritesABannedToken(string $banned): void
    {
        // When
        $occurrences = $this->occurrences($banned);

        // Then
        static::assertSame([], $occurrences, sprintf('"%s" is banned by section 8 of the specification.', $banned));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideBannedTokens(): iterable
    {
        // The property reads Text::of() replaces (M-12, I-12).
        yield 'textContent' => ['textContent'];
        yield 'nodeValue' => ['nodeValue'];
        yield 'innerHTML' => ['innerHTML'];
        // The time is the clock port's, in UTC (M-7).
        yield 'date_default_timezone_set()' => ['date_default_timezone_set('];
    }

    /**
     * Section 8, M-6
     */
    #[Test]
    public function itNeverComparesWithTheSpaceship(): void
    {
        // When
        $files = array_keys(array_filter(
            $this->sources(),
            $this->hasSpaceship(...),
        ));

        // Then
        static::assertSame([], $files);
    }

    /**
     * Section 8, M-7
     */
    #[Test]
    public function itNeverFillsATimeFromTheClock(): void
    {
        // When
        $formats = [];
        $filled = [];
        foreach ($this->sources() as $file => $source) {
            foreach ($this->formats($source) as $format) {
                $formats[] = $format;
                if (! str_starts_with($format, "'!") && ! str_contains($format, '|')) {
                    $filled[] = sprintf('%s: %s', $file, $format);
                }
            }
        }

        // Then
        static::assertNotSame([], $formats);
        static::assertSame([], $filled, 'Formats that read the clock: ' . implode(', ', $filled));
    }

    /**
     * @param list<string> $formats
     */
    #[Test]
    #[TestWith([
        "<?php DateTimeImmutable::createFromFormat('!Y-m-d', \$v);",
        false,
        ["'!Y-m-d'"],
    ], 'a format that resets')]
    #[TestWith([
        "<?php \\DateTimeImmutable::createFromFormat('Y-m-d', \$v);",
        false,
        ["'Y-m-d'"],
    ], 'a format that reads the clock')]
    #[TestWith([
        "<?php DateTimeImmutable::createFromFormat(\$format, \$v);",
        false,
        ['$format'],
    ], 'a format in a variable')]
    #[TestWith(['<?php return $a <=> $b;', true, []], 'a spaceship')]
    #[TestWith(["<?php return '\$a <=> \$b';", false, []], 'a spaceship in a string')]
    public function itFindsWhatItScansFor(string $source, bool $spaceship, array $formats): void
    {
        // When / Then
        static::assertSame([$spaceship, $formats], [$this->hasSpaceship($source), $this->formats($source)]);
    }

    private function hasSpaceship(string $source): bool
    {
        return array_any(PhpToken::tokenize($source), static fn (
            #[SensitiveParameter]
            PhpToken $token,
        ): bool => $token->is(T_SPACESHIP));
    }

    /**
     * @return list<string> as written, a literal with its quotes
     */
    private function formats(string $source): array
    {
        $tokens = array_values(array_filter(
            PhpToken::tokenize($source),
            static fn (#[SensitiveParameter] PhpToken $phpToken): bool => ! $phpToken->isIgnorable(),
        ));
        $formats = [];
        foreach ($tokens as $index => $token) {
            if (! ($token->is(T_STRING) && strtolower($token->text) === 'createfromformat' && ($tokens[$index - 1] ?? null)?->is(T_DOUBLE_COLON) === true)) {
                continue;
            }

            $formats[] = $tokens[$index + 2]->text ?? '';
        }

        return $formats;
    }

    /**
     * @return array<string, int> count by file of src/, comments and string literals left aside
     */
    private function occurrences(string $banned): array
    {
        $occurrences = [];
        foreach ($this->sources() as $path => $source) {
            $code = '';
            foreach (PhpToken::tokenize($source) as $phpToken) {
                $code .= $phpToken->isIgnorable() || $phpToken->is([T_CONSTANT_ENCAPSED_STRING, T_ENCAPSED_AND_WHITESPACE])
                    ? ' '
                    : $phpToken->text;
            }
            $count = substr_count(strtolower($code), strtolower($banned));
            if ($count > 0) {
                $occurrences[$path] = $count;
            }
        }
        ksort($occurrences);

        return $occurrences;
    }

    /**
     * @return array<string, string> source by path relative to src/
     */
    private function sources(): array
    {
        $directory = dirname(__DIR__, 3) . '/src/saml2-model/src';
        $sources = [];
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(
            $directory,
            RecursiveDirectoryIterator::SKIP_DOTS,
        ));
        foreach ($iterator as $file) {
            if (! $file instanceof SplFileInfo || $file->getExtension() !== 'php') {
                continue;
            }
            $source = file_get_contents($file->getPathname());
            static::assertIsString($source);
            $sources[substr($file->getPathname(), strlen($directory) + 1)] = $source;
        }

        return $sources;
    }
}
