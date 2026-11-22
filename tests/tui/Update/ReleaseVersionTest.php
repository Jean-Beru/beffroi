<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Update;

use Beffroi\Tui\Update\ReleaseVersion;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * The version of a release, read from its tag, and the line a release stays in.
 */
final class ReleaseVersionTest extends TestCase
{
    #[Test]
    public function aReleaseTagIsReadAsItsThreeNumbers(): void
    {
        // When
        $version = ReleaseVersion::fromTag('0.12.3');

        // Then
        static::assertSame(['0.12.3', 0, 12, 3], [$version?->tag, $version?->major, $version?->minor, $version?->patch]);
    }

    #[Test]
    #[DataProvider('provideTagsOfNoRelease')]
    public function aTagOfAnotherFormIsNoRelease(string $tag): void
    {
        // When / Then
        static::assertNull(ReleaseVersion::fromTag($tag));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideTagsOfNoRelease(): iterable
    {
        yield 'empty' => [''];
        yield 'prefixed' => ['v0.0.1'];
        yield 'two numbers' => ['0.1'];
        yield 'four numbers' => ['0.0.1.2'];
        yield 'a prerelease' => ['0.1.0-rc1'];
        yield 'a line break after it' => ["0.0.1\n"];
        yield 'a branch' => ['0.0.x'];
    }

    #[Test]
    #[DataProvider('provideVersionsOfTheLine')]
    public function aVersionIsInTheLineOfAnotherWhenTheirFirstTwoNumbersAreTheSame(string $tag, bool $inTheLine): void
    {
        // Given
        $running = ReleaseVersion::fromTag('0.1.4') ?? static::fail('0.1.4 is a release tag.');
        $other = ReleaseVersion::fromTag($tag) ?? static::fail(sprintf('%s is a release tag.', $tag));

        // When / Then
        static::assertSame($inTheLine, $other->isInTheLineOf($running));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideVersionsOfTheLine(): iterable
    {
        yield 'a patch above' => ['0.1.9', true];
        yield 'a patch below' => ['0.1.0', true];
        yield 'the next minor' => ['0.2.0', false];
        yield 'the next major' => ['1.1.4', false];
    }

    #[Test]
    #[DataProvider('provideOrders')]
    public function aVersionIsAboveAnotherByItsNumbersInTheirOrder(string $tag, bool $above): void
    {
        // Given
        $running = ReleaseVersion::fromTag('1.2.3') ?? static::fail('1.2.3 is a release tag.');
        $other = ReleaseVersion::fromTag($tag) ?? static::fail(sprintf('%s is a release tag.', $tag));

        // When / Then
        static::assertSame($above, $other->isAbove($running));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideOrders(): iterable
    {
        yield 'the same' => ['1.2.3', false];
        yield 'a patch above' => ['1.2.4', true];
        yield 'a patch of two digits' => ['1.2.10', true];
        yield 'a patch below' => ['1.2.2', false];
        yield 'a minor above with a lower patch' => ['1.3.0', true];
        yield 'a minor below with a higher patch' => ['1.1.9', false];
        yield 'a major above' => ['2.0.0', true];
    }
}
