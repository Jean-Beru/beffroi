<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Session;

use Beffroi\Core\Domain\Listing\Period;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\AuthenticationProofs;
use Beffroi\Core\Domain\Session\SessionQuestion;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Architecture §5.2
 */
final class SessionQuestionTest extends TestCase
{
    #[Test]
    public function aQuestionThatAsksNothingAdmitsEverySession(): void
    {
        // When / Then
        static::assertTrue(new SessionQuestion()->admits(Fixtures::session()));
    }

    #[Test]
    #[DataProvider('provideOpenings')]
    public function theDaysOfOpeningAdmitWhatWasOpenedOnThem(string $openedAt, bool $admitted): void
    {
        // Given
        $question = new SessionQuestion(opened: Period::ofDays(Fixtures::now(), Fixtures::now()));

        // When / Then
        static::assertSame($admitted, $question->admits(Fixtures::session(authenticatedAt: Fixtures::now()->modify($openedAt))));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideOpenings(): iterable
    {
        yield 'that day' => ['+1 hour', true];
        yield 'the day before' => ['-1 day', false];
    }

    #[Test]
    #[DataProvider('provideVisits')]
    public function theDaysOfTheLastVisitAdmitWhatWasLastSeenOnThem(string $seenAt, bool $admitted): void
    {
        // Given
        $question = new SessionQuestion(seen: Period::ofDays(Fixtures::now(), Fixtures::now()));
        $session = Fixtures::session(authenticatedAt: Fixtures::now()->modify('-2 days'));
        $session->touch(Fixtures::context(Fixtures::now()->modify($seenAt)), Fixtures::now()->modify('+1 day'));

        // When / Then
        static::assertSame($admitted, $question->admits($session));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideVisits(): iterable
    {
        yield 'that day' => ['+1 hour', true];
        yield 'the day before' => ['-1 day', false];
    }

    /**
     * RFC 8176 §2
     */
    #[Test]
    #[DataProvider('provideMethods')]
    public function theMethodAskedForAdmitsTheSessionsThatProvedIt(string $method, bool $admitted): void
    {
        // Given
        $session = Fixtures::session(proofs: AuthenticationProofs::of(new AuthenticationMethod(AuthenticationMethod::HARDWARE_KEY), Fixtures::now()));

        // When / Then
        static::assertSame($admitted, new SessionQuestion(provedWith: $method)->admits($session));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideMethods(): iterable
    {
        yield 'a method it proved' => [AuthenticationMethod::HARDWARE_KEY, true];
        yield 'a method it did not prove' => [AuthenticationMethod::PASSWORD, false];
    }
}
