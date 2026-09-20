<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Domain\Session;

use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Core\Domain\Session\AuthenticationPredicate;
use Heidi\Core\Domain\Session\AuthenticationProofs;
use Heidi\Core\Tests\Fixture\Fixtures;
use function in_array;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class AuthenticationPredicateTest extends TestCase
{
    /**
     * OIDC Core §5.5.1.1, architecture §3.2, decision 0010: a predicate on the proofs, every predicate
     * that holds holds, not only the strongest; a factor is the kind RFC 8176 §2 gives a method.
     *
     * @param list<AuthenticationPredicate> $satisfied
     */
    #[Test]
    #[DataProvider('provideProofsAndThePredicatesTheySatisfy')]
    public function aPredicateHoldsOnTheProofsItDescribes(AuthenticationProofs $proofs, array $satisfied): void
    {
        // When / Then
        foreach (AuthenticationPredicate::cases() as $predicate) {
            static::assertSame(in_array($predicate, $satisfied, true), $predicate->isSatisfiedBy($proofs), $predicate->value);
        }
    }

    /**
     * @return iterable<string, array{AuthenticationProofs, list<AuthenticationPredicate>}>
     */
    public static function provideProofsAndThePredicatesTheySatisfy(): iterable
    {
        $now = Fixtures::now();
        yield 'a password' => [AuthenticationProofs::of(AuthenticationMethod::password(), $now), [AuthenticationPredicate::SingleFactor]];
        yield 'a one-time password alone' => [AuthenticationProofs::of(new AuthenticationMethod('otp'), $now), [AuthenticationPredicate::SingleFactor]];
        yield 'a presence check alone' => [AuthenticationProofs::of(new AuthenticationMethod('user'), $now), [AuthenticationPredicate::SingleFactor]];
        yield 'a password and a PIN, one kind' => [AuthenticationProofs::of(AuthenticationMethod::password(), $now)->with(new AuthenticationMethod('pin'), $now), [AuthenticationPredicate::SingleFactor]];
        yield 'a password and a one-time password' => [AuthenticationProofs::of(AuthenticationMethod::password(), $now)->with(new AuthenticationMethod('otp'), $now), [AuthenticationPredicate::SingleFactor, AuthenticationPredicate::TwoFactors]];
        yield 'a password and a fingerprint' => [AuthenticationProofs::of(AuthenticationMethod::password(), $now)->with(new AuthenticationMethod('fpt'), $now), [AuthenticationPredicate::SingleFactor, AuthenticationPredicate::TwoFactors]];
        yield 'mfa asserted upstream' => [AuthenticationProofs::of(new AuthenticationMethod('mfa'), $now), [AuthenticationPredicate::SingleFactor, AuthenticationPredicate::TwoFactors]];
        yield 'a software key alone' => [AuthenticationProofs::of(new AuthenticationMethod('swk'), $now), [AuthenticationPredicate::SingleFactor, AuthenticationPredicate::PhishingResistant]];
        yield 'a hardware key alone' => [AuthenticationProofs::of(new AuthenticationMethod('hwk'), $now), [AuthenticationPredicate::SingleFactor, AuthenticationPredicate::PhishingResistant, AuthenticationPredicate::PhishingResistantHardware]];
        yield 'a password and a hardware key' => [AuthenticationProofs::of(AuthenticationMethod::password(), $now)->with(new AuthenticationMethod('hwk'), $now), AuthenticationPredicate::cases()];
    }
}
