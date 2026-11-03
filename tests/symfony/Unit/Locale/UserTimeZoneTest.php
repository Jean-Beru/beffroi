<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Locale;

use App\Locale\UserTimeZone;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Issue #469: the clock a date is read on. "zoneinfo" is a claim of OIDC Core §5.1 and not a setting of
 * this provider, so it is read as a zone rather than taken as one, the way UserLocale reads a language.
 */
final class UserTimeZoneTest extends TestCase
{
    #[Test]
    public function theZoneThePersonNamedAnswers(): void
    {
        // Given
        $user = self::userIn('Europe/London');

        // When / Then
        static::assertSame('Europe/London', new UserTimeZone()->of($user)->getName());
    }

    /**
     * A claim nobody can resolve is not a zone of this process, whatever was written in it: the clock of
     * the deployment answers, and nothing is refused.
     */
    #[Test]
    #[DataProvider('provideUnresolvableZones')]
    public function aZoneThisProcessCannotResolveLeavesTheClockOfTheDeployment(string $claimed): void
    {
        // Given
        $user = self::userIn($claimed);

        // When / Then
        static::assertSame(date_default_timezone_get(), new UserTimeZone()->of($user)->getName());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideUnresolvableZones(): iterable
    {
        yield 'a name nobody has' => ['Europe/Atlantis'];
        yield 'an offset rather than a zone' => ['+02:00'];
        yield 'an abbreviation' => ['CEST'];
        yield 'empty' => [''];
    }

    #[Test]
    public function aPersonWhoNamedNoZoneReadsTheClockOfTheDeployment(): void
    {
        // Given
        $user = self::userIn(null);

        // When / Then
        static::assertSame(date_default_timezone_get(), new UserTimeZone()->of($user)->getName());
    }

    /**
     * A page that shows a date to nobody in particular is answered the same way, which is what the pages
     * with no reader get.
     */
    #[Test]
    public function nobodyReadsTheClockOfTheDeployment(): void
    {
        // When / Then
        static::assertSame(date_default_timezone_get(), new UserTimeZone()->of(null)->getName());
    }

    private static function userIn(?string $zoneinfo): User
    {
        $user = Fixtures::user();
        $user->updateProfile(new Profile(zoneinfo: $zoneinfo), Fixtures::now());

        return $user;
    }
}
