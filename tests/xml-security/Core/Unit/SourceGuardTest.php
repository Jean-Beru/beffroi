<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit;

use function array_diff_key;
use function dirname;
use function file_get_contents;
use function is_file;
use function ksort;
use PhpToken;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;
use function sprintf;
use function strlen;
use function strtolower;
use function substr;
use function substr_count;
use const T_CONSTANT_ENCAPSED_STRING;
use const T_ENCAPSED_AND_WHITESPACE;

/**
 * Section 8, I-2, I-4, I-9, I-11, I-13, I-14, I-15
 */
final class SourceGuardTest extends TestCase
{
    /**
     * Section 8, I-2, I-4, I-9, I-11, section 6.6
     */
    #[Test]
    #[DataProvider('provideBannedTokens')]
    public function itNeverWritesABannedToken(string $token): void
    {
        // When
        $occurrences = $this->occurrences($token);

        // Then
        static::assertSame([], $occurrences, sprintf('"%s" is banned by section 8 of the specification.', $token));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideBannedTokens(): iterable
    {
        $tokens = [
            // One parser, one DOM (I-4).
            'DOMDocument',
            'DOMXPath',
            'DOMImplementation',
            'Dom\XPath',
            'SimpleXMLElement',
            'simplexml_',
            'xml_parser_create',
            'XMLReader',
            'XMLWriter',
            // No entity loader, no flag that loads a DTD or substitutes entities (I-2).
            'libxml_set_external_entity_loader',
            'libxml_disable_entity_loader',
            'LIBXML_NOENT',
            'LIBXML_DTDLOAD',
            'LIBXML_DTDATTR',
            'LIBXML_DTDVALID',
            'LIBXML_XINCLUDE',
            'LIBXML_PARSEHUGE',
            'LIBXML_NOBLANKS',
            'LIBXML_NOCDATA',
            'xinclude(',
            // Lookup by index, never by query (I-9, I-11, I-14).
            'getElementById(',
            'setIdAttribute',
            'getElementsByTagName',
            'querySelector',
            'XPath',
            // Closed for good (section 8).
            'createFromFile(',
            'C14NFile(',
            'saveXmlFile(',
            'importNode(',
            'adoptNode(',
            'createEntityReference(',
            'schemaValidate',
            'relaxNgValidate',
            // Read through Text::of() instead (section 6.4).
            'textContent',
            'nodeValue',
            'innerHTML',
            // No silencing, reflection, eval, dynamic call, file or network access.
            'error_reporting(',
            'Reflection',
            'eval(',
            'call_user_func',
            'file_get_contents(',
            'file_put_contents(',
            'fopen(',
            'fsockopen(',
            'curl_',
            'stream_',
        ];
        foreach ($tokens as $token) {
            yield $token => [$token];
        }
    }

    /**
     * Section 8, I-4, I-13, I-15
     */
    #[Test]
    #[DataProvider('provideConfinedCalls')]
    public function itConfinesACallToItsClass(string $token, string $file): void
    {
        // When
        $occurrences = $this->occurrences($token);

        // Then
        $elsewhere = array_diff_key($occurrences, [$file => true]);
        static::assertSame(
            [],
            $elsewhere,
            sprintf('"%s" is confined to %s by section 8 of the specification.', $token, $file),
        );
        if (is_file($this->sourceDirectory() . '/' . $file)) {
            static::assertSame(
                [$file => 1],
                $occurrences,
                sprintf('"%s" is called exactly once, in %s.', $token, $file),
            );
        }
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideConfinedCalls(): iterable
    {
        yield 'createFromString() in Loader' => ['createFromString(', 'Core/Loader.php'];
        yield 'createEmpty() in DocumentFactory' => ['createEmpty(', 'Core/DocumentFactory.php'];
        yield 'C14N() in Canonicalizer' => ['C14N(', 'Core/Canonicalizer.php'];
        yield 'saveXml() in Serializer' => ['saveXml(', 'Core/Serializer.php'];
    }

    /**
     * @return array<string, int> count of $token per file of src/ holding it
     */
    private function occurrences(string $token): array
    {
        $occurrences = [];
        foreach ($this->sourceFiles() as $path => $code) {
            $count = substr_count(strtolower($code), strtolower($token));
            if ($count > 0) {
                $occurrences[$path] = $count;
            }
        }
        ksort($occurrences);

        return $occurrences;
    }

    /**
     * @return array<string, string> code with comments and strings blanked, keyed by the path relative to src/
     */
    private function sourceFiles(): array
    {
        $directory = $this->sourceDirectory();
        $files = [];
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(
            $directory,
            RecursiveDirectoryIterator::SKIP_DOTS,
        ));
        foreach ($iterator as $file) {
            if (! $file instanceof SplFileInfo || $file->getExtension() !== 'php') {
                continue;
            }
            $source = file_get_contents($file->getPathname());
            static::assertNotFalse($source);
            $code = '';
            foreach (PhpToken::tokenize($source) as $phpToken) {
                if ($phpToken->isIgnorable() || $phpToken->is([T_CONSTANT_ENCAPSED_STRING, T_ENCAPSED_AND_WHITESPACE])) {
                    $code .= ' ';
                    continue;
                }
                $code .= $phpToken->text;
            }
            $files[substr($file->getPathname(), strlen($directory) + 1)] = $code;
        }

        return $files;
    }

    private function sourceDirectory(): string
    {
        return dirname(__DIR__, 4) . '/src/xml-security/src';
    }
}
