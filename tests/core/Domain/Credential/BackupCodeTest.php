<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Credential;

use Beffroi\Core\Bridge\Random\PlatformRandomness;
use Beffroi\Core\Domain\Credential\BackupCode;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Exception\LogicException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use function str_split;

/**
 * Architecture §3.1
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
