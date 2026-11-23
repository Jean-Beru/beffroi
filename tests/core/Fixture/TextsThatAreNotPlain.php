<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

/**
 * A text broken in its middle, where no trimming reaches, by each kind of character a line of text may not hold.
 */
final class TextsThatAreNotPlain
{
    /**
     * @return iterable<string, array{string}>
     */
    public static function around(string $text): iterable
    {
        yield 'an escape sequence that erases the line above' => [$text . "\e[2K\e[1A\e[2K" . $text];
        yield 'a line feed' => [$text . "\nYour account is locked" . $text];
        yield 'a NUL byte' => [$text . "\0" . $text];
        yield 'a right-to-left override' => [$text . "\u{202E}gnp.exe" . $text];
        yield 'a zero-width space' => [$text . "\u{200B}" . $text];
        yield 'a line separator' => [$text . "\u{2028}" . $text];
    }
}
