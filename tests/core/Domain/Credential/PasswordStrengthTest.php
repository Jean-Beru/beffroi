<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Credential;

use Beffroi\Core\Domain\Credential\PasswordStrength;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * How hard a password is to guess, in bits, and the rung that number falls on (NIST SP 800-63B §5.1.1.2).
 *
 * **These vectors are what holds the two estimates together.** The same count is written twice, here and
 * in the script the browser runs (password-strength.js), and there is no JavaScript runner in this
 * repository: these rungs are what the script was written against, and where the two disagree the refusal
 * is the server's. A vector changed here is a vector to replay by hand against the script.
 */
final class PasswordStrengthTest extends TestCase
{
    /**
     * The alphabets a password draws from give the pool, the distinct characters give what each position
     * is worth, and a character written twice is worth less than the first one.
     */
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
    }

    /**
     * Counted over the bytes, which is what the script counts too: eight accented characters are sixteen
     * bytes drawn from two of them.
     */
    #[Test]
    public function anAccentedPasswordIsCountedOverItsBytes(): void
    {
        // When / Then
        static::assertSame(28.0, PasswordStrength::of('éééééééé')->bits);
    }

    /**
     * What each alphabet adds to the pool, pinned to the bit: one vector per alphabet, holding both of
     * its boundary bytes and nothing of any other, so that a rung is not the only thing the estimate is
     * held to. These are the figures the script in the browser has to come out with, and the capitals
     * counting apart from the rest is the one place the two could quietly disagree.
     */
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
        // nothing of a password is worth nothing, and never one bit
        yield 'nothing at all' => ['', 0.0];
        // the ten digits, with 0 and 9 among them
        yield 'digits alone' => ['0369258147', 33.219280948873624];
        // the twenty-six capitals, with A and Z among them, which count apart from the rest
        yield 'capitals alone' => ['AZQJXKBMWP', 47.004397181410916];
        // the twenty-six others, with a and z among them
        yield 'letters alone' => ['azqjxkbmwp', 47.004397181410916];
        // a control character and a space: the space is a symbol and not a control one, and the two
        // alphabets are counted both, where either alone would come out the same
        yield 'a tabulation and a space' => ["ab\tcd ef", 52.188495648456104];
        // the other end of the control characters, which is one byte and not a range
        yield 'a delete and a space' => ["abcdef\x7f ", 52.188495648456104];
        // the first byte beyond ASCII, which is where that alphabet starts and not where it opens
        yield 'one byte beyond ascii' => ["abcdefg\x80", 58.13429232555921];
        // the pool is the alphabets added and never one taken from another
        yield 'digits and a tabulation' => ["ab12\t34cd", 54.97672011100352];
    }

    /**
     * A floor is read off the rung and never off the bits, so that the page, the script and the value
     * object all ask the same question.
     */
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
