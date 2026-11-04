<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Support;

use function array_map;
use function array_unique;
use function array_values;
use function count;
use function explode;
use function file_get_contents;
use function implode;
use PhpToken;
use function preg_match;
use function preg_match_all;
use function preg_quote;
use function preg_replace;
use function preg_split;
use function range;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;
use function sort;
use SplFileInfo;
use function sprintf;
use function str_contains;
use function str_starts_with;
use function strlen;
use function strpos;
use function substr;
use const T_DOC_COMMENT;
use function trim;

/**
 * Reads the invariants B-1 to B-13 and the corpus rows of spec/bindings.md, and the test docblocks citing them.
 */
final readonly class Traceability
{
    private string $specification;

    private string $docblocks;

    public function __construct(string $specificationPath, string $testsDirectory)
    {
        $specification = file_get_contents($specificationPath);
        if ($specification === false) {
            throw new RuntimeException(sprintf('%s cannot be read.', $specificationPath));
        }
        $this->specification = $specification;
        $this->docblocks = $this->docblocks($testsDirectory);
    }

    /**
     * The invariants section 4 declares, "B-1" to "B-13".
     *
     * @return list<string>
     */
    public function invariants(): array
    {
        preg_match_all('~^- \*\*B-(\d+)\.~m', $this->specification, $matches);

        return array_map(static fn (string $number): string => 'B-' . $number, $matches[1]);
    }

    /**
     * @return list<string>
     */
    public function citedInvariants(): array
    {
        preg_match_all('~\bB-(\d+)\b~', $this->docblocks, $cited);

        return array_values(array_unique(array_map(static fn (string $number): string => 'B-' . $number, $cited[1])));
    }

    /**
     * @return array<int, string> numbered from 1
     */
    public function tableRows(string $heading): array
    {
        $section = $this->section($heading, "\n### ");
        $rows = [];
        $inTable = false;
        foreach (explode("\n", $section) as $line) {
            if (! str_starts_with($line, '|')) {
                if ($inTable) {
                    break;
                }
                continue;
            }
            if (! $inTable) {
                $inTable = true;
                continue;
            }
            if (preg_match('~^\|[-| ]+\|$~', $line) === 1) {
                continue;
            }
            $rows[count($rows) + 1] = trim($line, '| ');
        }

        return $rows;
    }

    /**
     * The rows the docblocks cite: "§9.2 row 6", "§9.2 rows 1 to 4", "§9.2 rows 18 and 19", "§9.2 rows 4, 6, 10 and
     * 12", a citation broken over two lines of a docblock included.
     *
     * @return list<int>
     */
    public function citedRows(string $section): array
    {
        preg_match_all(
            '~§' . preg_quote($section, '~') . '\s+rows?\s+([0-9]+(?:(?:,\s+|\s+and\s+|\s+to\s+)[0-9]+)*)~',
            $this->docblocks,
            $matches,
        );
        $rows = [];
        foreach ($matches[1] as $citation) {
            $parts = preg_split('~,\s+|\s+and\s+~', $citation);
            if ($parts === false) {
                throw new RuntimeException(sprintf('The citation "%s" cannot be split.', $citation));
            }
            foreach ($parts as $part) {
                if (str_contains($part, ' to ')) {
                    [$from, $to] = explode(' to ', $part);
                    foreach (range((int) $from, (int) $to) as $row) {
                        $rows[] = $row;
                    }
                    continue;
                }
                $rows[] = (int) $part;
            }
        }
        sort($rows);

        return array_values(array_unique($rows));
    }

    private function docblocks(string $directory): string
    {
        $docblocks = [];
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(
            $directory,
            RecursiveDirectoryIterator::SKIP_DOTS,
        ));
        foreach ($iterator as $file) {
            if (! $file instanceof SplFileInfo || $file->getExtension() !== 'php') {
                continue;
            }
            $source = file_get_contents($file->getPathname());
            if ($source === false) {
                throw new RuntimeException(sprintf('%s cannot be read.', $file->getPathname()));
            }
            foreach (PhpToken::tokenize($source) as $token) {
                if (! $token->is(T_DOC_COMMENT)) {
                    continue;
                }

                $docblocks[] = (string) preg_replace('~^\s*\*+ ?~m', '', $token->text);
            }
        }

        return implode("\n", $docblocks);
    }

    private function section(string $from, string $until): string
    {
        $start = strpos($this->specification, $from);
        if ($start === false) {
            throw new RuntimeException(sprintf('The specification has no "%s".', $from));
        }
        $end = strpos($this->specification, $until, $start + strlen($from));

        return $end === false
            ? substr($this->specification, $start)
            : substr($this->specification, $start, $end - $start);
    }
}
