<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Session;

use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\AuthenticationPredicate;
use function in_array;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class AuthenticationPredicateTest extends TestCase
{
    /**
     * OIDC Core §5.5.1.1, architecture §3.2, decision 0010: a predicate reads which methods were proven,
     * every predicate that holds holds, not only the strongest; a factor is the kind RFC 8176 §2 gives a
     * method. When a method was proven is no business of a predicate, so none of these cases dates one.
     *
     * @param list<AuthenticationMethod> $methods
     * @param list<AuthenticationPredicate> $satisfied
     */
    #[Test]
    #[DataProvider('provideMethodsAndThePredicatesTheySatisfy')]
    public function aPredicateHoldsOnTheMethodsItDescribes(array $methods, array $satisfied): void
    {
        // When / Then
        foreach (AuthenticationPredicate::cases() as $predicate) {
            static::assertSame(in_array($predicate, $satisfied, true), $predicate->isSatisfiedBy($methods), $predicate->value);
        }
    }

    /**
     * @return iterable<string, array{list<AuthenticationMethod>, list<AuthenticationPredicate>}>
     */
    public static function provideMethodsAndThePredicatesTheySatisfy(): iterable
    {
        yield 'nothing proven' => [[], []];
        yield 'a password' => [
            [AuthenticationMethod::password()],
            [AuthenticationPredicate::SingleFactor],
        ];
        yield 'a one-time password alone' => [[new AuthenticationMethod('otp')], [AuthenticationPredicate::SingleFactor]];
        yield 'a presence check alone' => [[new AuthenticationMethod('user')], [AuthenticationPredicate::SingleFactor]];
        yield 'a password and a PIN, one kind' => [
            [AuthenticationMethod::password(), new AuthenticationMethod('pin')],
            [AuthenticationPredicate::SingleFactor],
        ];
        yield 'a password and a one-time password' => [
            [AuthenticationMethod::password(), new AuthenticationMethod('otp')],
            [AuthenticationPredicate::SingleFactor, AuthenticationPredicate::TwoFactors],
        ];
        yield 'a password and a fingerprint' => [
            [AuthenticationMethod::password(), new AuthenticationMethod('fpt')],
            [AuthenticationPredicate::SingleFactor, AuthenticationPredicate::TwoFactors],
        ];
        yield 'mfa asserted upstream' => [
            [new AuthenticationMethod('mfa')],
            [AuthenticationPredicate::SingleFactor, AuthenticationPredicate::TwoFactors],
        ];
        yield 'a software key alone' => [
            [new AuthenticationMethod('swk')],
            [AuthenticationPredicate::SingleFactor, AuthenticationPredicate::PhishingResistant],
        ];
        yield 'a hardware key alone' => [
            [new AuthenticationMethod('hwk')],
            [AuthenticationPredicate::SingleFactor, AuthenticationPredicate::PhishingResistant, AuthenticationPredicate::PhishingResistantHardware],
        ];
        yield 'a password and a hardware key' => [
            [AuthenticationMethod::password(), new AuthenticationMethod('hwk')],
            AuthenticationPredicate::cases(),
        ];
    }
}
