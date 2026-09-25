<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Domain\Credential;

use Heidi\Core\Bridge\Random\PlatformRandomness;
use Heidi\Core\Domain\Credential\BackupCode;
use Heidi\Core\Bridge\Password\Algorithm\Argon2id;
use Heidi\Core\Domain\Credential\PasswordHash;
use Heidi\Core\Exception\LogicException;
use Heidi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use function str_split;

/**
 * Architecture §3.1: a backup code is a hash and the instant it was spent, each one accepted once.
 */
final class BackupCodeTest extends TestCase
{
    #[Test]
    public function aCodeIsTenCharactersOfTheAlphabetInTwoGroups(): void
    {
        // When
        $code = BackupCode::spelledBy(self::drawn());

        // Then
        static::assertMatchesRegularExpression('/^[A-Z2-7]{5}-[A-Z2-7]{5}$/', $code);
    }

    /**
     * Two thousand characters spelled: each of the thirty-two appears, none of them is skipped.
     */
    #[Test]
    public function everyCharacterOfTheAlphabetIsSpelled(): void
    {
        // Given
        $spelled = '';
        for ($i = 0; $i < 200; ++$i) {
            $spelled .= BackupCode::spelledBy(self::drawn());
        }

        // When / Then
        foreach (str_split(BackupCode::ALPHABET) as $character) {
            static::assertStringContainsString($character, $spelled);
        }
    }

    /**
     * The five low bits of each byte pick the character, and nothing above them is read.
     */
    #[Test]
    public function theBytesGivenSpellTheCode(): void
    {
        // When / Then
        static::assertSame('AAAAA-AAAAA', BackupCode::spelledBy(str_repeat("\x20", BackupCode::LENGTH)));
    }

    #[Test]
    public function twoDrawsSpellDifferentCodes(): void
    {
        // When / Then
        static::assertNotSame(BackupCode::spelledBy(self::drawn()), BackupCode::spelledBy(self::drawn()));
    }

    #[Test]
    #[DataProvider('provideTypedCodes')]
    public function whatTheUserTypedIsComparedInUpperCaseWithoutSeparators(string $typed): void
    {
        // When / Then
        static::assertSame('K7Q2MX9PL4', BackupCode::normalize($typed));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideTypedCodes(): iterable
    {
        yield 'as shown' => ['K7Q2M-X9PL4'];
        yield 'lower case' => ['k7q2m-x9pl4'];
        yield 'without the hyphen' => ['K7Q2MX9PL4'];
        yield 'with spaces' => [' K7Q2M X9PL4 '];
    }

    #[Test]
    public function aFreshCodeIsNotSpent(): void
    {
        // When
        $code = new BackupCode(self::hash());

        // Then
        static::assertFalse($code->isSpent());
        static::assertNull($code->usedAt);
    }

    #[Test]
    public function aSpentCodeKeepsItsHashAndTheInstant(): void
    {
        // Given
        $code = new BackupCode(self::hash());

        // When
        $spent = $code->spend(Fixtures::now());

        // Then
        static::assertTrue($spent->isSpent());
        static::assertSame($code->hash, $spent->hash);
        static::assertEquals(Fixtures::now(), $spent->usedAt);
        static::assertFalse($code->isSpent());
    }

    #[Test]
    public function aCodeIsSpentOnce(): void
    {
        // Given
        $spent = new BackupCode(self::hash(), Fixtures::now());

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('A backup code is spent once.');

        // When
        $spent->spend(Fixtures::now()->modify('+1 hour'));
    }

    private static function hash(): PasswordHash
    {
        return new PasswordHash(new Argon2id(), '$argon2id$code');
    }

    private static function drawn(): string
    {
        return new PlatformRandomness()->bytes(BackupCode::LENGTH);
    }
}
