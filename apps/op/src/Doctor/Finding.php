<?php

declare(strict_types=1);

namespace App\Doctor;

/**
 * What one point of "beffroi:doctor" looked at and what it found (issue #196): the line that names the
 * point, whether this deployment answers for it, and what the reader is owed when it does not.
 *
 * A green finding says the number it read, because a point that says nothing but "yes" is a point nobody
 * can tell from a point that was never looked at; a red one says what it found, what that costs and what
 * to do about it, because what a doctor finds is by construction what nothing else shows.
 */
final readonly class Finding
{
    /**
     * @param list<string> $lines
     */
    private function __construct(
        public string $about,
        public bool $green,
        public array $lines,
    ) {
    }

    public static function green(string $about, string $says): self
    {
        return new self($about, true, [$says]);
    }

    /**
     * @param list<string> $lines what was found, then what it costs, then what makes it green
     */
    public static function red(string $about, array $lines): self
    {
        return new self($about, false, $lines);
    }
}
