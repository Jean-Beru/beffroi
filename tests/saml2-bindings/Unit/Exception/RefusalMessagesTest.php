<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit\Exception;

use function array_filter;
use function array_map;
use function array_values;
use function basename;
use function dirname;
use function file_get_contents;
use function glob;
use function in_array;
use function ltrim;
use PhpToken;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;
use function preg_match;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SensitiveParameter;
use SplFileInfo;
use function sprintf;
use function strlen;
use function strrchr;
use function substr;
use const T_CONSTANT_ENCAPSED_STRING;
use const T_NEW;

/**
 * §9.3 row 14, B-11
 */
final class RefusalMessagesTest extends TestCase
{
    /**
     * Section 5.4
     */
    private const array PROGRAMMING_ERRORS = ['InvalidArgumentException', 'LogicException'];

    /**
     * §9.3 row 14, B-11
     */
    #[Test]
    public function everyRefusalNamesItsRule(): void
    {
        // Given
        $messages = [];
        foreach ($this->sources() as $file => $source) {
            foreach ($this->messages($source) as $message) {
                $messages[] = [$file, $message];
            }
        }

        // When
        $unnamed = array_values(array_filter(
            $messages,
            static fn (array $message): bool => ! self::namesItsRule($message[1]),
        ));

        // Then
        static::assertNotSame([], $messages);
        static::assertSame([], array_map(static fn (array $message): string => sprintf(
            '%s: %s',
            $message[0],
            $message[1],
        ), $unnamed));
    }

    /**
     * B-11
     */
    #[Test]
    #[TestWith(['A query string carries both message parameters (B-1).', true], 'an invariant')]
    #[TestWith(['A SAMLEncoding other than DEFLATE is refused (section 8).', true], 'a section')]
    #[TestWith(['maxInflatedBytes must be between 1 and 1048576 (section 7).', true], 'a bound')]
    #[TestWith(['The RelayState changed after signing (B-2, B-9).', true], 'two invariants')]
    #[TestWith(['A query string carries both message parameters (B-1)', false], 'no final period')]
    #[TestWith(['A query string carries both message parameters.', false], 'no rule')]
    #[TestWith(['The signature does not verify (D-5).', false], 'a rule of another package')]
    #[TestWith(['The RelayState is too long (B-9): refused.', false], 'a rule in the middle')]
    public function itReadsTheRuleAMessageEndsWith(string $message, bool $named): void
    {
        // When / Then
        static::assertSame($named, self::namesItsRule($message));
    }

    /**
     * @param list<string> $expected
     */
    #[Test]
    #[TestWith([
        "<?php throw new MalformedParameters('A query string carries both message parameters (B-1).');",
        ['A query string carries both message parameters (B-1).'],
    ], 'a literal')]
    #[TestWith([
        "<?php throw new LimitExceeded(sprintf('The query string is over %s (B-7).', 'maxQueryStringBytes'));",
        ['The query string is over %s (B-7).'],
    ], 'a format')]
    #[TestWith([
        "<?php throw new Exception\\MalformedEncoding('A percent-escape is malformed (B-8).');",
        ['A percent-escape is malformed (B-8).'],
    ], 'a qualified name')]
    #[TestWith([
        "<?php throw new \\InvalidArgumentException('The RelayState is empty (B-9).');",
        ['The RelayState is empty (B-9).'],
    ], 'a programming error')]
    #[TestWith(["<?php throw new InvalidRelayState(\$message);", ['<not a literal>']], 'a variable')]
    #[TestWith(["<?php throw new RuntimeException('Not ours.');", []], 'another exception')]
    public function itFindsTheMessagesOfAnException(string $source, array $expected): void
    {
        // When / Then
        static::assertSame($expected, $this->messages($source));
    }

    private static function namesItsRule(string $message): bool
    {
        return preg_match('~\((?:B-\d+|section \d+(?:\.\d+)*)(?:, (?:B-\d+|section \d+(?:\.\d+)*))*\)\.\z~', $message) === 1;
    }

    /**
     * @return list<string>
     */
    private function messages(string $source): array
    {
        $tokens = array_values(array_filter(
            PhpToken::tokenize($source),
            static fn (#[SensitiveParameter] PhpToken $phpToken): bool => ! $phpToken->isIgnorable(),
        ));
        $exceptions = [...$this->refusals(), ...self::PROGRAMMING_ERRORS];
        $messages = [];
        foreach ($tokens as $index => $token) {
            if (! $token->is(T_NEW) || ! in_array($this->shortName($tokens[$index + 1]->text ?? ''), $exceptions, true)) {
                continue;
            }
            $messages[] = $this->argument($tokens, $index + 3);
        }

        return $messages;
    }

    private function shortName(string $name): string
    {
        $last = strrchr($name, '\\');

        return $last === false ? $name : ltrim($last, '\\');
    }

    /**
     * @param list<PhpToken> $tokens
     */
    private function argument(array $tokens, int $index): string
    {
        $token = $tokens[$index] ?? null;
        if ($token?->text === 'sprintf') {
            $token = $tokens[$index + 2] ?? null;
        }

        return $token?->is(T_CONSTANT_ENCAPSED_STRING) === true ? $this->unquote($token->text) : '<not a literal>';
    }

    private function unquote(string $literal): string
    {
        return substr($literal, 1, strlen($literal) - 2);
    }

    /**
     * @return list<string>
     */
    private function refusals(): array
    {
        $files = glob(dirname(__DIR__, 4) . '/src/saml2-bindings/src/Exception/*.php');
        static::assertIsArray($files);

        return array_values(array_filter(
            array_map(static fn (string $file): string => basename($file, '.php'), $files),
            static fn (string $name): bool => $name !== 'BindingRefused',
        ));
    }

    /**
     * @return array<string, string> source keyed by its path relative to src/
     */
    private function sources(): array
    {
        $directory = dirname(__DIR__, 4) . '/src/saml2-bindings/src';
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
