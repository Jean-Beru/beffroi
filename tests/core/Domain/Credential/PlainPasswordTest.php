<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Credential;

use Beffroi\Core\Domain\Credential\PasswordRefusal;
use Beffroi\Core\Domain\Credential\PlainPassword;
use Beffroi\Core\Exception\PasswordRefusedException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use function strlen;
use function substr;

/**
 * What a password has to be before anything hashes it: the lower bound of NIST SP 800-63B §5.1.1.2 in
 * characters, the upper bound the password hashers refuse to go past (CVE-2013-1443) in bytes, and the
 * rung the estimate of the search space has to reach. Whoever sets a password holds one of these, so the
 * rules are not ones a caller can go around.
 */
final class PlainPasswordTest extends TestCase
{
    /**
     * Twenty-eight characters drawing on two alphabets: past every rule, which is what the rest of the
     * suite poses.
     */
    private const string A_PASSWORD = 'correct horse battery staple';

    #[Test]
    public function aPasswordLongAndVariedEnoughIsHeld(): void
    {
        // When / Then
        static::assertSame(self::A_PASSWORD, new PlainPassword(self::A_PASSWORD)->value);
    }

    /**
     * The lower bound is counted in characters, not in bytes: eight accented characters are sixteen bytes
     * and are not what the length rule refuses, the estimate being what refuses them.
     */
    #[Test]
    public function eightMultibyteCharactersAreNotTooShort(): void
    {
        // Given
        $password = 'éééééééé';

        // When
        try {
            new PlainPassword($password);
            static::fail('A password of eight repeated characters is refused.');
        } catch (PasswordRefusedException $exception) {
            // Then
            static::assertSame(PasswordRefusal::TooWeak, $exception->refusal);
        }
    }

    #[Test]
    public function sevenCharactersAreRefused(): void
    {
        // Then
        $this->expectException(PasswordRefusedException::class);
        $this->expectExceptionMessageIs('A password is at least 8 characters long.');

        // When
        new PlainPassword('seven77');
    }

    /**
     * The upper bound is counted in bytes, not in characters: it is what a hasher swallows.
     */
    #[Test]
    public function fourThousandAndNinetySixBytesAreAccepted(): void
    {
        // Given
        $password = self::bytes(PlainPassword::MAXIMUM_BYTES);

        // When / Then
        static::assertSame(PlainPassword::MAXIMUM_BYTES, strlen(new PlainPassword($password)->value));
    }

    #[Test]
    public function oneByteMoreIsRefused(): void
    {
        // Then
        $this->expectException(PasswordRefusedException::class);
        $this->expectExceptionMessageIs('A password is at most 4096 bytes long.');

        // When
        new PlainPassword(self::bytes(PlainPassword::MAXIMUM_BYTES + 1));
    }

    /**
     * The estimate and never a composition rule (§5.1.1.2): what is refused is short of length and of
     * alphabet at once, and nothing is refused for holding no capital, no digit and no symbol.
     */
    #[Test]
    #[DataProvider('provideGuessablePasswords')]
    public function aGuessablePasswordIsRefused(string $password): void
    {
        // Then
        $this->expectException(PasswordRefusedException::class);
        $this->expectExceptionMessageIs('A password this short of length and of alphabet is guessed: make it longer, or several words.');

        // When
        new PlainPassword($password);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideGuessablePasswords(): iterable
    {
        yield 'a word and a digit' => ['password1'];
        yield 'one character repeated' => [str_repeat('a', 24)];
        yield 'a word written twice' => ['passwordpassword'];
        yield 'eight of every alphabet' => ['Ab3$Cd4%'];
    }

    /**
     * Length is one way past the floor and an alphabet is another: neither is asked for on its own.
     */
    #[Test]
    #[DataProvider('provideAcceptedPasswords')]
    public function aPasswordPastTheFloorIsHeld(string $password): void
    {
        // When / Then
        static::assertSame($password, new PlainPassword($password)->value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAcceptedPasswords(): iterable
    {
        yield 'four words of letters only' => [self::A_PASSWORD];
        yield 'thirteen letters and nothing else' => ['mindfulbakery'];
        yield 'eleven of every alphabet' => ['Tr0ub4dor&3'];
    }

    /**
     * A password of exactly that many bytes, past the floor: the four words repeated, which no length
     * makes guessable.
     */
    private static function bytes(int $length): string
    {
        return substr(str_repeat(self::A_PASSWORD . ' ', 1 + (int) ($length / strlen(self::A_PASSWORD))), 0, $length);
    }
}
