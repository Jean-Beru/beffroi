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
 * OIDC Core §5.1
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
