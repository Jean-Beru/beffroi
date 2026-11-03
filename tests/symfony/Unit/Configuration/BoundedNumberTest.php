<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Configuration;

use App\Configuration\BoundedNumber;
use App\Configuration\TokensSection;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

/**
 * Issues #911 and #915: a number the tree bounds is held to the same bounds when the container builds the value it
 * is handed as, which is where a number an environment variable carries is first a number. RFC 6749 §4.1.2 is the
 * bound of a code.
 */
final class BoundedNumberTest extends TestCase
{
    #[Test]
    #[DataProvider('provideNumbersWithinTheBounds')]
    public function aNumberWithinTheBoundsIsTheLifetime(int $seconds): void
    {
        // When
        $lifetime = BoundedNumber::interval($seconds, 'authorization_code_ttl', TokensSection::MAX_AUTHORIZATION_CODE_TTL);

        // Then
        static::assertSame($seconds, $lifetime->s);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideNumbersWithinTheBounds(): iterable
    {
        yield 'a second' => [1];
        yield 'the bound itself' => [TokensSection::MAX_AUTHORIZATION_CODE_TTL];
    }

    #[Test]
    #[DataProvider('provideNumbersOutsideTheBounds')]
    public function aNumberOutsideTheBoundsIsRefusedByTheNodeItWasWrittenUnder(int $seconds): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs(\sprintf(
            'The "beffroi" configuration key "authorization_code_ttl" is a number of seconds from 1 to 600, %d given.',
            $seconds,
        ));

        // When
        BoundedNumber::interval($seconds, 'authorization_code_ttl', TokensSection::MAX_AUTHORIZATION_CODE_TTL);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideNumbersOutsideTheBounds(): iterable
    {
        yield 'nothing' => [0];
        yield 'a negative number' => [-60];
        yield 'a second past the bound' => [TokensSection::MAX_AUTHORIZATION_CODE_TTL + 1];
    }

    /**
     * A lifetime the tree bounds below only, the one of an access token for instance, is as long as it is
     * written.
     */
    #[Test]
    public function aLifetimeWithNoMaximumIsAsLongAsItIsWritten(): void
    {
        // When
        $lifetime = BoundedNumber::interval(7_776_000, 'access_token_ttl');

        // Then
        static::assertSame(7_776_000, $lifetime->s);
    }

    /**
     * Issue #913: below a second, what such a lifetime dates is expired when it is issued.
     */
    #[Test]
    #[DataProvider('provideNumbersBelowASecond')]
    public function aLifetimeWithNoMaximumIsRefusedBelowASecond(int $seconds): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs(\sprintf(
            'The "beffroi" configuration key "access_token_ttl" is a number of seconds of at least 1, %d given.',
            $seconds,
        ));

        // When
        BoundedNumber::interval($seconds, 'access_token_ttl');
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideNumbersBelowASecond(): iterable
    {
        yield 'nothing' => [0];
        yield 'a negative number' => [-1];
    }

    /**
     * Issue #915: a leeway or a cooldown the tree lets be none is none at its floor, and refused below it.
     */
    #[Test]
    public function aNumberOfSecondsTheTreeLetsBeNoneIsNoneAtItsFloor(): void
    {
        // When
        $leeway = BoundedNumber::interval(0, 'dpop.leeway', minimum: 0);

        // Then
        static::assertSame(0, $leeway->s);
    }

    #[Test]
    public function aNumberOfSecondsBelowAFloorOfNoneIsRefused(): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('The "beffroi" configuration key "dpop.leeway" is a number of seconds of at least 0, -1 given.');

        // When
        BoundedNumber::interval(-1, 'dpop.leeway', minimum: 0);
    }

    /**
     * Issue #915: a call to a third party is given a tenth of a second at least.
     */
    #[Test]
    #[DataProvider('provideTimeouts')]
    public function aTimeoutAtItsFloorOrAboveIsTheTimeACallIsGiven(float $seconds): void
    {
        // When
        $timeout = BoundedNumber::timeout($seconds, 'back_channel_logout.timeout');

        // Then
        static::assertSame($seconds, $timeout->seconds);
    }

    /**
     * @return iterable<string, array{float}>
     */
    public static function provideTimeouts(): iterable
    {
        yield 'the floor' => [0.1];
        yield 'five seconds' => [5.0];
    }

    /**
     * Issue #915: a timeout of nothing would be a call that waits for ever, HttpClient reading a "max_duration" of zero
     * as no limit at all.
     */
    #[Test]
    #[DataProvider('provideTimeoutsBelowTheFloor')]
    public function aTimeoutBelowItsFloorIsRefused(float $seconds, string $given): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs(\sprintf(
            'The "beffroi" configuration key "back_channel_logout.timeout" is a number of seconds of at least 0.1, %s given.',
            $given,
        ));

        // When
        BoundedNumber::timeout($seconds, 'back_channel_logout.timeout');
    }

    /**
     * @return iterable<string, array{float, string}>
     */
    public static function provideTimeoutsBelowTheFloor(): iterable
    {
        yield 'nothing' => [0.0, '0'];
        yield 'a hundredth of a second' => [0.01, '0.01'];
        yield 'a negative number' => [-1.0, '-1'];
    }

    /**
     * Issue #915: a third party may answer one byte at least.
     */
    #[Test]
    public function aNumberOfBytesOfOneAtLeastIsWhatAThirdPartyMayAnswer(): void
    {
        // When
        $limit = BoundedNumber::bytes(1, 'request_objects.max_size');

        // Then
        static::assertSame(1, $limit->bytes);
    }

    #[Test]
    public function aNumberOfBytesBelowOneIsRefused(): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('The "beffroi" configuration key "request_objects.max_size" is a number of bytes of at least 1, 0 given.');

        // When
        BoundedNumber::bytes(0, 'request_objects.max_size');
    }

    /**
     * An object a number reaches as it is holds it to the floor of its node (NotificationRetryPolicy, LoadBudget).
     */
    #[Test]
    public function aNumberBelowTheFloorOfItsNodeIsRefusedInTheWordsOfWhatItCounts(): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('The "beffroi" configuration key "back_channel_logout.retries" is a number of retries of at least 0, -1 given.');

        // When
        BoundedNumber::assertAtLeast(-1, 0, 'back_channel_logout.retries', 'retries');
    }
}
