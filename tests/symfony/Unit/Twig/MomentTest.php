<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Twig;

use App\Locale\Moments;
use App\Locale\UserTimeZone;
use App\Twig\MomentExtension;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Tests\Fixture\Fixtures;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Translation\LocaleSwitcher;

final class MomentTest extends TestCase
{
    #[Test]
    public function aMomentIsReadOnTheClockOfThePerson(): void
    {
        // When
        $written = self::moment('en')->moment(self::instant(), self::userIn('Europe/London'));

        // Then
        static::assertStringContainsString('15:04', $written);
        static::assertStringContainsString('BST', $written);
    }

    #[Test]
    public function aMomentSaysWhichClockItIsOn(): void
    {
        // When
        $written = self::moment('en')->moment(self::instant(), self::userIn('UTC'));

        // Then
        static::assertStringContainsString('14:04', $written);
        static::assertStringContainsString('UTC', $written);
    }

    #[Test]
    public function aClockWithNoAbbreviationIsNamedByItsOffset(): void
    {
        // When
        $written = self::moment('en')->moment(self::instant(), self::userIn('Asia/Bangkok'));

        // Then
        static::assertStringContainsString('21:04', $written);
        static::assertStringContainsString('GMT+7', $written);
    }

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
        return new MomentExtension(new Moments(new UserTimeZone()), new LocaleSwitcher($locale, []));
    }

    private static function userIn(string $zoneinfo): User
    {
        $user = Fixtures::user();
        $user->updateProfile(new Profile(zoneinfo: $zoneinfo), Fixtures::now());

        return $user;
    }
}
