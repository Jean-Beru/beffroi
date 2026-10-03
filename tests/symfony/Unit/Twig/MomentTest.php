<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Twig;

use Beffroi\Bundle\Locale\UserTimeZone;
use Beffroi\Bundle\Twig\MomentExtension;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Tests\Fixture\Fixtures;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Translation\LocaleSwitcher;

/**
 * Issue #469: a moment as the person in front of the page reads it, in the language the page is written
 * in, on the clock that person keeps, and always saying which clock that is.
 *
 * What ICU writes for a language is ICU's and changes with its version, so what is asserted here is what
 * the provider decides: which clock, which hour on it, and whose words. Pinning the spacing of a locale
 * would be pinning the library.
 */
final class MomentTest extends TestCase
{
    /**
     * 14:04 UTC is an hour later in London that day, and the clock is named so a reader can check it.
     * The hour alone is asserted: how a language writes the half of the day is that language's.
     */
    #[Test]
    public function aMomentIsReadOnTheClockOfThePerson(): void
    {
        // When
        $written = self::moment('en')->moment(self::instant(), self::userIn('Europe/London'));

        // Then
        static::assertStringContainsString('3:04', $written);
        static::assertStringContainsString('GMT+1', $written);
    }

    #[Test]
    public function aMomentSaysWhichClockItIsOn(): void
    {
        // When
        $written = self::moment('en')->moment(self::instant(), self::userIn('UTC'));

        // Then
        static::assertStringContainsString('2:04', $written);
        static::assertStringContainsString('UTC', $written);
    }

    /**
     * A clock with no abbreviation of its own is named by its offset, which is as checkable.
     */
    #[Test]
    public function aClockWithNoAbbreviationIsNamedByItsOffset(): void
    {
        // When
        $written = self::moment('en')->moment(self::instant(), self::userIn('Asia/Bangkok'));

        // Then
        static::assertStringContainsString('9:04', $written);
        static::assertStringContainsString('GMT+7', $written);
    }

    /**
     * The language decides the order and the words of a date, which is why the same instant on the same
     * clock is not written the same way on a page in French and on a page in English.
     */
    #[Test]
    public function theLanguageOfThePageDecidesTheWordsOfTheDate(): void
    {
        // Given
        $reader = self::userIn('UTC');

        // When
        $english = self::moment('en')->moment(self::instant(), $reader);
        $french = self::moment('fr')->moment(self::instant(), $reader);

        // Then
        static::assertStringContainsString('Oct', $english);
        static::assertStringContainsString('oct', $french);
        static::assertNotSame($english, $french);
    }

    #[Test]
    public function aMomentShownToNobodyIsReadOnTheClockOfTheDeployment(): void
    {
        // Given
        $deployment = new UserTimeZone()->of(null)->getName();

        // When
        $written = self::moment('en')->moment(self::instant());

        // Then
        static::assertSame(self::moment('en')->moment(self::instant(), self::userIn($deployment)), $written);
    }

    private static function instant(): DateTimeImmutable
    {
        return new DateTimeImmutable('2026-10-03T14:04:00+00:00');
    }

    private static function moment(string $locale): MomentExtension
    {
        return new MomentExtension(new UserTimeZone(), new LocaleSwitcher($locale, []));
    }

    private static function userIn(string $zoneinfo): User
    {
        $user = Fixtures::user();
        $user->updateProfile(new Profile(zoneinfo: $zoneinfo), Fixtures::now());

        return $user;
    }
}
