<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Device;

use function hash;
use Beffroi\Oidc\Domain\Device\UserCode;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strlen;

/**
 * RFC 8628 §6.1: the code is read off one screen and typed on another, so its alphabet has no character a
 * reader takes for another and what the user typed is compared after the separators are dropped.
 */
final class UserCodeTest extends TestCase
{
    #[Test]
    public function itIsShownInTwoGroupsForTheEye(): void
    {
        // When
        $code = UserCode::of('BCDFGHJK');

        // Then
        static::assertSame('BCDFGHJK', $code->value);
        static::assertSame('BCDF-GHJK', $code->formatted());
    }

    /**
     * RFC 8628 §6.1: twenty consonants, no vowel, so that no eight of them spell a word somebody has to
     * read aloud to a stranger, and no digit, a digit and a letter being what a reader mixes up.
     */
    #[Test]
    public function itsAlphabetIsTwentyConsonantsAndNothingElse(): void
    {
        // When / Then
        static::assertSame(20, strlen(UserCode::ALPHABET));
        foreach (['A', 'E', 'I', 'O', 'U', 'Y', '0', '1', '2', '8', '9'] as $character) {
            static::assertStringNotContainsString($character, UserCode::ALPHABET, $character);
        }
    }

    /**
     * What the provider keeps of a code is its SHA-256, as of every other value it hands out.
     */
    #[Test]
    public function whatIsKeptOfACodeIsItsDigest(): void
    {
        // When / Then
        static::assertSame(hash('sha256', 'BCDFGHJK'), UserCode::of('BCDFGHJK')->hash());
    }

    #[Test]
    #[DataProvider('provideTypedCodes')]
    public function whatTheUserTypedIsComparedWithoutItsSeparators(string $typed, string $normalized): void
    {
        // When / Then
        static::assertSame($normalized, UserCode::normalize($typed));
    }

    /**
     * BCP 10027 §2: the user compares the code on the page with the code on the screen they read it from, so
     * the page shows it the way that screen does whatever form it was typed in.
     */
    #[Test]
    #[DataProvider('provideShownCodes')]
    public function whatTheUserTypedIsShownBackAsTheApplianceShowsIt(string $typed, string $shown): void
    {
        // When / Then
        static::assertSame($shown, UserCode::shown($typed));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideShownCodes(): iterable
    {
        yield 'the bare code' => ['BCDFGHJK', 'BCDF-GHJK'];
        yield 'as it was shown' => ['BCDF-GHJK', 'BCDF-GHJK'];
        yield 'in lower case' => ['bcdf-ghjk', 'BCDF-GHJK'];
        yield 'with spaces' => [' BCDF GHJK ', 'BCDF-GHJK'];
    }

    /**
     * What is not a code is shown back as it was read, so that a wrong character can be corrected rather
     * than hidden behind a grouping that would not hold anyway.
     */
    #[Test]
    #[DataProvider('provideTypedValuesThatAreNotACode')]
    public function whatIsNotACodeIsShownBackAsItWasTyped(string $typed, string $shown): void
    {
        // When / Then
        static::assertSame($shown, UserCode::shown($typed));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideTypedValuesThatAreNotACode(): iterable
    {
        yield 'too short' => ['BCDF', 'BCDF'];
        yield 'too long' => ['BCDFGHJKL', 'BCDFGHJKL'];
        yield 'a character of no alphabet' => ['BCDF-GHJ1', 'BCDFGHJ1'];
        yield 'a vowel' => ['bcdf-ghja', 'BCDFGHJA'];
        yield 'nothing at all' => ['', ''];
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideTypedCodes(): iterable
    {
        yield 'the bare code' => ['BCDFGHJK', 'BCDFGHJK'];
        yield 'as it was shown' => ['BCDF-GHJK', 'BCDFGHJK'];
        yield 'in lower case' => ['bcdf-ghjk', 'BCDFGHJK'];
        yield 'with spaces' => [' BCDF GHJK ', 'BCDFGHJK'];
        yield 'with several separators' => ['BCDF--GHJK', 'BCDFGHJK'];
        yield 'nothing at all' => ['', ''];
    }

    /**
     * Normalizing says nothing of whether what is left is a code: a form filled with anything is refused
     * rather than trimmed into something.
     */
    #[Test]
    #[DataProvider('provideCodesThatAreNotOne')]
    public function aValueThatIsNotACodeOfThisProviderIsNotWellFormed(string $value): void
    {
        // When / Then
        static::assertFalse(UserCode::isWellFormed($value));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideCodesThatAreNotOne(): iterable
    {
        yield 'empty' => [''];
        yield 'too short' => ['BCDFGHJ'];
        yield 'too long' => ['BCDFGHJKL'];
        yield 'a character of no alphabet of ours' => ['BCDFGHJ1'];
        yield 'a vowel' => ['BCDFGHJA'];
        yield 'lower case' => ['bcdfghjk'];
        yield 'the separator still in it' => ['BCDF-GHJ'];
    }

    #[Test]
    public function itRefusesToBeBuiltFromWhatThisProviderNeverDraws(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('A user code is 8 characters of "BCDFGHJKLMNPQRSTVWXZ"');

        // When
        UserCode::of('bcdf-ghjk');
    }
}
