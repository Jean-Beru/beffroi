<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Credential;

use Beffroi\Core\Domain\Credential\PasswordStrength;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * NIST SP 800-63B §3.1.1.2
 *
 * The script the browser runs, password-strength.js, counts the same and has no runner here: a vector changed
 * here is replayed by hand against it.
 */
final class PasswordStrengthTest extends TestCase
{
    #[Test]
    #[DataProvider('provideEstimates')]
    public function theEstimateIsTheRungTheVectorLandsOn(string $password, int $rung): void
    {
        // When / Then
        static::assertSame($rung, PasswordStrength::of($password)->rung);
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function provideEstimates(): iterable
    {
        yield 'nothing at all' => ['', PasswordStrength::NOTHING];
        yield 'a word and a digit' => ['password1', PasswordStrength::NOTHING];
        yield 'one letter twenty-four times' => [str_repeat('a', 24), PasswordStrength::NOTHING];
        yield 'a word written twice' => ['passwordpassword', PasswordStrength::NOTHING];
        yield 'eight of every alphabet' => ['Ab3$Cd4%', PasswordStrength::NOTHING];
        yield 'thirteen letters' => ['mindfulbakery', PasswordStrength::WEAK];
        yield 'eleven of every alphabet' => ['Tr0ub4dor&3', PasswordStrength::WEAK];
        yield 'sixteen letters and a space' => ['anvil carpet bone', PasswordStrength::MEDIUM];
        yield 'twenty-two letters and spaces' => ['nine lives of a quiet', PasswordStrength::STRONG];
        yield 'four words of letters' => ['correct horse battery staple', PasswordStrength::VERY_STRONG];
        yield 'a euro sign fifteen times' => [str_repeat('€', 15), PasswordStrength::NOTHING];
        yield 'an emoji twelve times' => [str_repeat('😀', 12), PasswordStrength::NOTHING];
        yield 'a letter and fourteen zero-width spaces' => ['a' . str_repeat("\u{200B}", 14), PasswordStrength::NOTHING];
        yield 'three accented words' => ['élève café thé', PasswordStrength::MEDIUM];
    }

    #[Test]
    public function anAccentedPasswordIsCountedOverItsCharacters(): void
    {
        // When / Then
        static::assertSame(7.0, PasswordStrength::of('éééééééé')->bits);
    }

    #[Test]
    #[DataProvider('provideAlphabets')]
    public function eachAlphabetAddsWhatItAddsToThePool(string $password, float $bits): void
    {
        // When / Then
        static::assertSame($bits, PasswordStrength::of($password)->bits);
    }

    /**
     * @return iterable<string, array{string, float}>
     */
    public static function provideAlphabets(): iterable
    {
        yield 'nothing at all' => ['', 0.0];
        yield 'digits alone' => ['0369258147', 33.219280948873624];
        yield 'capitals alone' => ['AZQJXKBMWP', 47.004397181410916];
        yield 'letters alone' => ['azqjxkbmwp', 47.004397181410916];
        yield 'a tabulation and a space' => ["ab\tcd ef", 52.188495648456104];
        yield 'a delete and a space' => ["abcdef\x7f ", 52.188495648456104];
        yield 'one character beyond ascii' => ['abcdefgé', 58.13429232555921];
        yield 'a byte that is no character' => ["abcdefg\x80", 58.13429232555921];
        yield 'digits and a tabulation' => ["ab12\t34cd", 54.97672011100352];
    }

    #[Test]
    #[DataProvider('provideFloors')]
    public function anEstimateReachesTheRungsAtAndBelowItsOwn(int $floor, bool $reached): void
    {
        // Given
        $estimate = PasswordStrength::of('Tr0ub4dor&3');

        // When / Then
        static::assertSame($reached, $estimate->reaches($floor));
    }

    /**
     * @return iterable<string, array{int, bool}>
     */
    public static function provideFloors(): iterable
    {
        yield 'nothing' => [PasswordStrength::NOTHING, true];
        yield 'its own' => [PasswordStrength::WEAK, true];
        yield 'the one above' => [PasswordStrength::MEDIUM, false];
        yield 'the highest' => [PasswordStrength::VERY_STRONG, false];
    }
}
