<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Archive;

use Beffroi\Core\Domain\Archive\ArchivePassword;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * Issue #483: the passphrase a person chose to have their archive leave under it. The floor is refused and
 * never warned about (decision 0006), because the container fixes its own derivation and what is left is
 * the length of what was typed.
 */
final class ArchivePasswordTest extends TestCase
{
    #[Test]
    public function aPassphraseOfTheMinimumLengthIsHeldAsItWasTyped(): void
    {
        // Given
        $typed = str_repeat('a', ArchivePassword::MINIMUM_LENGTH);

        // When / Then
        static::assertSame($typed, new ArchivePassword($typed)->value);
    }

    #[Test]
    #[DataProvider('provideTooShort')]
    public function aPassphraseShorterThanTheFloorIsRefused(string $typed): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A passphrase for an archive is at least 16 characters long.');

        // When
        new ArchivePassword($typed);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideTooShort(): iterable
    {
        yield 'nothing typed' => [''];
        yield 'a word' => ['correct'];
        yield 'one character short' => [str_repeat('a', ArchivePassword::MINIMUM_LENGTH - 1)];
    }

    /**
     * Counted in characters and not in bytes, because that is what a person typed: four words of accented
     * letters are shorter in characters than the bytes they take.
     */
    #[Test]
    public function theFloorCountsCharactersAndNotBytes(): void
    {
        // Given
        $typed = str_repeat('é', ArchivePassword::MINIMUM_LENGTH - 1);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A passphrase for an archive is at least 16 characters long.');

        // When
        new ArchivePassword($typed);
    }

    /**
     * The upper bound bounds a field of a request and nothing cryptographic: a megabyte pasted into it is
     * not a passphrase.
     */
    #[Test]
    public function aPassphrasePastTheUpperBoundIsRefused(): void
    {
        // Given
        $typed = str_repeat('a', ArchivePassword::MAXIMUM_BYTES + 1);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A passphrase for an archive is at most 256 bytes long.');

        // When
        new ArchivePassword($typed);
    }
}
