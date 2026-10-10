<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Credential;

use Beffroi\Core\Domain\Credential\PasswordDigest;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * The one shape of a password that may leave this process: the SHA-1 a list of compromised passwords is
 * searched by, split where the search splits it (Pwned Passwords, range API).
 */
final class PasswordDigestTest extends TestCase
{
    /**
     * The known SHA-1 of "password", upper case, which is what the endpoint answers in.
     */
    private const string PASSWORD_DIGEST = '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8';

    #[Test]
    public function theDigestOfAPasswordIsItsUpperCaseSha1(): void
    {
        // When / Then
        static::assertSame(self::PASSWORD_DIGEST, PasswordDigest::of('password')->value);
    }

    /**
     * Five characters of forty go out, which is the bucket of about a million passwords the endpoint is
     * addressed by.
     */
    #[Test]
    public function fiveCharactersAreWhatLeaves(): void
    {
        // When / Then
        static::assertSame('5BAA6', PasswordDigest::of('password')->prefix());
    }

    /**
     * The thirty-five that are left never leave: they are compared against what the bucket answered.
     */
    #[Test]
    public function thirtyFiveCharactersAreWhatIsComparedHere(): void
    {
        // When / Then
        static::assertSame('1E4C9B93F3F0682250B6CF8331B7EE68FD8', PasswordDigest::of('password')->suffix());
    }

    #[Test]
    #[DataProvider('provideStringsThatAreNoDigest')]
    public function aStringThatIsNoDigestIsRefused(string $value): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A password digest is 40 hexadecimal characters in upper case.');

        // When
        new PasswordDigest($value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideStringsThatAreNoDigest(): iterable
    {
        yield 'empty' => [''];
        yield 'one character short' => [str_repeat('A', 39)];
        yield 'one character long' => [str_repeat('A', 41)];
        yield 'lower case' => ['5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8'];
        yield 'not hexadecimal' => [str_repeat('G', 40)];
    }
}
