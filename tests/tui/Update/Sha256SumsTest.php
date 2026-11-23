<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Update;

use Beffroi\Tui\Update\ReleaseVersion;
use Beffroi\Tui\Update\SelfUpdateException;
use Beffroi\Tui\Update\Sha256Sums;
use function file_get_contents;
use function hash;
use function sprintf;
use function str_repeat;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The `SHA256SUMS` of a release, as `sha256sum` of GNU coreutils writes it.
 */
final class Sha256SumsTest extends TestCase
{
    #[Test]
    public function theDigestOfAFileIsTheOneOfItsLine(): void
    {
        // Given
        $sums = Sha256Sums::parse((string) file_get_contents(__DIR__ . '/../Fixture/Release/SHA256SUMS'));

        // When / Then
        static::assertSame('8a5c33b3c3a5633f40a4d5683799047b204efda8d0c7b3b63380a01a658f701c', $sums->digestOf('beffroi-tui-linux-x86_64'));
    }

    #[Test]
    public function aLineInBinaryModeGivesItsDigestToo(): void
    {
        // Given
        $sums = Sha256Sums::parse("f426e530171b9adea6176a27aa494f021a79610ac7d86ba90b15c513097943ed *beffroi-tui.phar\n");

        // When / Then
        static::assertSame('f426e530171b9adea6176a27aa494f021a79610ac7d86ba90b15c513097943ed', $sums->digestOf('beffroi-tui.phar'));
    }

    #[Test]
    public function theSumsOfAReleaseNameItsTag(): void
    {
        // Given
        $sums = Sha256Sums::parse(sprintf("%s  beffroi-tui.phar\n%s  release\n", str_repeat('0', 64), hash('sha256', "0.1.0\n")));

        // When / Then
        static::assertTrue($sums->areOf(self::version('0.1.0')));
    }

    #[Test]
    #[DataProvider('provideSumsOfAnotherRelease')]
    public function theSumsOfAnotherReleaseAreNotOfIt(string $text): void
    {
        // Given
        $sums = Sha256Sums::parse($text);

        // When / Then
        static::assertFalse($sums->areOf(self::version('0.1.1')));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideSumsOfAnotherRelease(): iterable
    {
        yield 'another tag' => [sprintf("%s  release\n", hash('sha256', "0.1.0\n"))];
        yield 'the tag without its line feed' => [sprintf("%s  release\n", hash('sha256', '0.1.1'))];
        yield 'no tag at all' => [sprintf("%s  beffroi-tui.phar\n", str_repeat('0', 64))];
    }

    #[Test]
    public function aFileTheSumsDoNotNameIsRefused(): void
    {
        // Given
        $sums = Sha256Sums::parse("f426e530171b9adea6176a27aa494f021a79610ac7d86ba90b15c513097943ed  beffroi-tui.phar\n");

        // Then
        $this->expectException(SelfUpdateException::class);
        $this->expectExceptionMessageIs('SHA256SUMS gives no digest of beffroi-tui-linux-x86_64.');

        // When
        $sums->digestOf('beffroi-tui-linux-x86_64');
    }

    #[Test]
    #[DataProvider('provideLinesOfAnotherForm')]
    public function aLineOfAnotherFormRefusesTheWholeFile(string $text, string $message): void
    {
        // Then
        $this->expectException(SelfUpdateException::class);
        $this->expectExceptionMessageIs($message);

        // When
        Sha256Sums::parse($text);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideLinesOfAnotherForm(): iterable
    {
        yield 'empty' => ['', 'Line 1 of SHA256SUMS is not a digest followed by a name.'];
        yield 'an uppercase digest' => [
            "F426E530171B9ADEA6176A27AA494F021A79610AC7D86BA90B15C513097943ED  beffroi-tui.phar\n",
            'Line 1 of SHA256SUMS is not a digest followed by a name.',
        ];
        yield 'a short digest' => ["f426e530  beffroi-tui.phar\n", 'Line 1 of SHA256SUMS is not a digest followed by a name.'];
        yield 'one space' => [
            "f426e530171b9adea6176a27aa494f021a79610ac7d86ba90b15c513097943ed beffroi-tui.phar\n",
            'Line 1 of SHA256SUMS is not a digest followed by a name.',
        ];
        yield 'a blank line between two' => [
            "f426e530171b9adea6176a27aa494f021a79610ac7d86ba90b15c513097943ed  beffroi-tui.phar\n\n8a5c33b3c3a5633f40a4d5683799047b204efda8d0c7b3b63380a01a658f701c  beffroi-tui-linux-x86_64\n",
            'Line 2 of SHA256SUMS is not a digest followed by a name.',
        ];
    }

    #[Test]
    public function aNameGivenTwiceRefusesTheWholeFile(): void
    {
        // Then
        $this->expectException(SelfUpdateException::class);
        $this->expectExceptionMessageIs('SHA256SUMS gives the digest of beffroi-tui.phar twice.');

        // When
        Sha256Sums::parse("f426e530171b9adea6176a27aa494f021a79610ac7d86ba90b15c513097943ed  beffroi-tui.phar\n8a5c33b3c3a5633f40a4d5683799047b204efda8d0c7b3b63380a01a658f701c  beffroi-tui.phar\n");
    }

    private static function version(string $tag): ReleaseVersion
    {
        return ReleaseVersion::fromTag($tag) ?? static::fail(sprintf('%s is a release tag.', $tag));
    }
}
