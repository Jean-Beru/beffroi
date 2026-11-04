<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Validation;

use Beffroi\Saml2\Model\Validation\TimeBounds;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.2, section 7, M-7
 */
final class TimeBoundsTest extends TestCase
{
    /**
     * Section 7
     */
    #[Test]
    public function itHasTheDefaultsOfSection7(): void
    {
        // When
        $bounds = new TimeBounds();

        // Then
        static::assertSame([180, 300, 3_600], [$bounds->clockSkew, $bounds->maxMessageAge, $bounds->maxBearerWindow]);
    }

    /**
     * Section 7
     */
    #[Test]
    #[DataProvider('provideClockSkews')]
    public function itAcceptsAClockSkewFromOneSecondToItsCeiling(int $seconds): void
    {
        // When
        $bounds = new TimeBounds(clockSkew: $seconds);

        // Then
        static::assertSame($seconds, $bounds->clockSkew);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideClockSkews(): iterable
    {
        yield '1 second' => [1];
        yield 'the ceiling, 300 seconds' => [300];
    }

    /**
     * Section 7, section 5.8
     */
    #[Test]
    #[DataProvider('provideClockSkewsOutOfRange')]
    public function itRefusesAClockSkewOutOfItsRange(int $seconds): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('clockSkew must be between 1 and 300 seconds (section 7).');

        // When
        new TimeBounds(clockSkew: $seconds);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideClockSkewsOutOfRange(): iterable
    {
        yield '0 seconds' => [0];
        yield 'a negative skew' => [-180];
        yield 'one over the ceiling, 301 seconds' => [301];
    }

    /**
     * Section 7
     */
    #[Test]
    #[DataProvider('provideMessageAges')]
    public function itAcceptsAMessageAgeFromOneSecondToItsCeiling(int $seconds): void
    {
        // When
        $bounds = new TimeBounds(maxMessageAge: $seconds);

        // Then
        static::assertSame($seconds, $bounds->maxMessageAge);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideMessageAges(): iterable
    {
        yield '1 second' => [1];
        yield 'the ceiling, 3600 seconds' => [3_600];
    }

    /**
     * Section 7, section 5.8
     */
    #[Test]
    #[DataProvider('provideMessageAgesOutOfRange')]
    public function itRefusesAMessageAgeOutOfItsRange(int $seconds): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('maxMessageAge must be between 1 and 3600 seconds (section 7).');

        // When
        new TimeBounds(maxMessageAge: $seconds);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideMessageAgesOutOfRange(): iterable
    {
        yield '0 seconds' => [0];
        yield 'one over the ceiling, 3601 seconds' => [3_601];
    }

    /**
     * Section 7
     */
    #[Test]
    #[DataProvider('provideBearerWindows')]
    public function itAcceptsABearerWindowFromOneSecondToItsCeiling(int $seconds): void
    {
        // When
        $bounds = new TimeBounds(maxBearerWindow: $seconds);

        // Then
        static::assertSame($seconds, $bounds->maxBearerWindow);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideBearerWindows(): iterable
    {
        yield '1 second' => [1];
        yield 'the ceiling, 86400 seconds' => [86_400];
    }

    /**
     * Section 7, section 5.8
     */
    #[Test]
    #[DataProvider('provideBearerWindowsOutOfRange')]
    public function itRefusesABearerWindowOutOfItsRange(int $seconds): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('maxBearerWindow must be between 1 and 86400 seconds (section 7).');

        // When
        new TimeBounds(maxBearerWindow: $seconds);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideBearerWindowsOutOfRange(): iterable
    {
        yield '0 seconds' => [0];
        yield 'one over the ceiling, 86401 seconds' => [86_401];
    }
}
