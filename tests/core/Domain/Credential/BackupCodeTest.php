<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Domain\Credential;

use Heidi\Core\Domain\Credential\BackupCode;
use Heidi\Core\Domain\Credential\PasswordAlgorithm;
use Heidi\Core\Domain\Credential\PasswordHash;
use Heidi\Core\Exception\LogicException;
use Heidi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_split;

/**
 * Architecture §3.1: a backup code is a hash and the instant it was spent, each one accepted once.
 */
final class BackupCodeTest extends TestCase
{
    #[Test]
    public function aGeneratedCodeIsTenCharactersOfTheAlphabetInTwoGroups(): void
    {
        // When
        $code = BackupCode::generate();

        // Then
        static::assertMatchesRegularExpression('/^[A-Z2-7]{5}-[A-Z2-7]{5}$/', $code);
    }

    /**
     * Two thousand characters drawn: each of the thirty-two appears, none of them is skipped by the draw.
     */
    #[Test]
    public function everyCharacterOfTheAlphabetIsDrawn(): void
    {
        // Given
        $drawn = '';
        for ($i = 0; $i < 200; ++$i) {
            $drawn .= BackupCode::generate();
        }

        // When / Then
        foreach (str_split(BackupCode::ALPHABET) as $character) {
            static::assertStringContainsString($character, $drawn);
        }
    }

    #[Test]
    public function twoGeneratedCodesDiffer(): void
    {
        // When / Then
        static::assertNotSame(BackupCode::generate(), BackupCode::generate());
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
        return new PasswordHash(PasswordAlgorithm::Argon2id, '$argon2id$code');
    }
}
