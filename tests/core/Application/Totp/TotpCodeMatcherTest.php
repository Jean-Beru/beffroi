<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Application\Totp;

use DateTimeImmutable;
use Heidi\Core\Application\Totp\TotpCodeMatcher;
use Heidi\Core\Tests\Fixture\Totps;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function substr;

/**
 * RFC 6238 §5.2: a code is looked for at the current step and one step on each side, no further.
 */
final class TotpCodeMatcherTest extends TestCase
{
    private DateTimeImmutable $now;

    private TotpCodeMatcher $matcher;

    protected function setUp(): void
    {
        // the second of a step, so that the drift is one of steps, not of seconds
        $this->now = new DateTimeImmutable('2026-09-20T12:00:15+00:00');
        $this->matcher = new TotpCodeMatcher(Totps::algorithm());
    }

    #[Test]
    #[DataProvider('provideStepsInTheWindow')]
    public function aCodeOfTheWindowIsMatchedToItsStep(int $drift): void
    {
        // Given
        $step = Totps::stepAt($this->now) + $drift;

        // When
        $matched = $this->matcher->matchingStep(Totps::secret(), Totps::algorithm()->codeAt(Totps::secret(), $step), $this->now);

        // Then
        static::assertSame($step, $matched);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideStepsInTheWindow(): iterable
    {
        yield 'one step early' => [-1];
        yield 'the current step' => [0];
        yield 'one step late' => [1];
    }

    #[Test]
    #[DataProvider('provideStepsOutOfTheWindow')]
    public function aCodeOutsideTheWindowMatchesNothing(int $drift): void
    {
        // Given
        $code = Totps::algorithm()->codeAt(Totps::secret(), Totps::stepAt($this->now) + $drift);

        // When / Then
        static::assertNull($this->matcher->matchingStep(Totps::secret(), $code, $this->now));
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideStepsOutOfTheWindow(): iterable
    {
        yield 'two steps early' => [-2];
        yield 'two steps late' => [2];
        yield 'an hour late' => [120];
    }

    #[Test]
    public function theSpacesAUserTypesBetweenTheDigitsAreDropped(): void
    {
        // Given
        $code = Totps::codeAt($this->now);
        $typed = ' ' . substr($code, 0, 3) . ' ' . substr($code, 3) . ' ';

        // When / Then
        static::assertSame(Totps::stepAt($this->now), $this->matcher->matchingStep(Totps::secret(), $typed, $this->now));
    }

    #[Test]
    #[DataProvider('provideNotCodes')]
    public function whatIsNotSixDigitsMatchesNothing(string $typed): void
    {
        // When / Then
        static::assertFalse(TotpCodeMatcher::looksLikeCode($typed));
        static::assertNull($this->matcher->matchingStep(Totps::secret(), $typed, $this->now));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNotCodes(): iterable
    {
        yield 'empty' => [''];
        yield 'five digits' => ['28708'];
        yield 'seven digits' => ['2870820'];
        yield 'letters' => ['28708a'];
        yield 'a backup code' => ['K7Q2M-X9PL4'];
    }

    #[Test]
    public function aWrongCodeOfSixDigitsMatchesNothing(): void
    {
        // Given
        $code = Totps::codeAt($this->now);
        $wrong = $code[0] === '9' ? '0' . substr($code, 1) : '9' . substr($code, 1);

        // When / Then
        static::assertNull($this->matcher->matchingStep(Totps::secret(), $wrong, $this->now));
    }

    /**
     * The first step there is has no step before it: nothing is asked of the brick for a negative one.
     */
    #[Test]
    public function theStepBeforeTheEpochIsNotTried(): void
    {
        // Given
        $epoch = new DateTimeImmutable('@0');

        // When / Then
        static::assertSame(0, $this->matcher->matchingStep(Totps::secret(), Totps::algorithm()->codeAt(Totps::secret(), 0), $epoch));
    }
}
