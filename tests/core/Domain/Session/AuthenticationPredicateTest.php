<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Session;

use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\AuthenticationPredicateInterface;
use Beffroi\Core\Domain\Session\PhishingResistant;
use Beffroi\Core\Domain\Session\PhishingResistantHardware;
use Beffroi\Core\Domain\Session\SingleFactor;
use Beffroi\Core\Domain\Session\TwoFactors;
use Beffroi\Core\Tests\Fixture\Predicates;
use function in_array;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0010
 */
final class AuthenticationPredicateTest extends TestCase
{
    /**
     * OIDC Core §5.5.1.1, Architecture §3.2, Decision 0010, RFC 8176 §2
     *
     * @param list<AuthenticationMethod> $methods
     * @param list<string> $satisfied
     */
    #[Test]
    #[DataProvider('provideMethodsAndThePredicatesTheySatisfy')]
    public function aPredicateHoldsOnTheMethodsItDescribes(array $methods, array $satisfied): void
    {
        // When / Then
        foreach (Predicates::all() as $predicate) {
            static::assertSame(in_array($predicate->name(), $satisfied, true), $predicate->isSatisfiedBy($methods), $predicate->name());
        }
    }

    /**
     * Decision 0025
     *
     * @param list<AuthenticationMethod> $methods
     * @param list<string> $admitting
     */
    #[Test]
    #[DataProvider('provideCredentialsAndTheFloorsThatAdmitThem')]
    public function aFloorAdmitsACredentialWhoseProofsItReads(array $methods, array $admitting): void
    {
        // When / Then
        foreach (Predicates::all() as $predicate) {
            static::assertSame(in_array($predicate->name(), $admitting, true), $predicate->admits($methods), $predicate->name());
        }
    }

    /**
     * Architecture §4.6
     */
    #[Test]
    public function theSingleFactorIsTheOnePredicateThatHoldsOnEveryLogin(): void
    {
        // When / Then
        foreach (Predicates::all() as $predicate) {
            static::assertSame($predicate->name() === SingleFactor::NAME, $predicate->holdsOnEveryLogin(), $predicate->name());
        }
    }

    #[Test]
    #[DataProvider('providePredicatesAndTheirNames')]
    public function aPredicateNamesItself(AuthenticationPredicateInterface $predicate, string $name): void
    {
        // When / Then
        static::assertSame($name, $predicate->name());
    }

    /**
     * @return iterable<string, array{AuthenticationPredicateInterface, string}>
     */
    public static function providePredicatesAndTheirNames(): iterable
    {
        yield 'the single factor' => [new SingleFactor(), 'single_factor'];
        yield 'two factors' => [new TwoFactors(), 'two_factors'];
        yield 'phishing resistant' => [new PhishingResistant(), 'phishing_resistant'];
        yield 'phishing resistant, hardware' => [new PhishingResistantHardware(), 'phishing_resistant_hardware'];
    }

    /**
     * @return iterable<string, array{list<AuthenticationMethod>, list<string>}>
     */
    public static function provideCredentialsAndTheFloorsThatAdmitThem(): iterable
    {
        yield 'a credential that could prove nothing, a revoked one' => [[], []];
        yield 'a password' => [
            [AuthenticationMethod::password()],
            [TwoFactors::NAME, SingleFactor::NAME],
        ];
        yield 'a one-time code, a TOTP or a backup code' => [
            [new AuthenticationMethod('otp')],
            [TwoFactors::NAME, SingleFactor::NAME],
        ];
        yield 'a synced passkey' => [
            [new AuthenticationMethod('swk'), new AuthenticationMethod('user')],
            [PhishingResistant::NAME, TwoFactors::NAME, SingleFactor::NAME],
        ];
        yield 'a passkey bound to its authenticator' => [
            [new AuthenticationMethod('hwk'), new AuthenticationMethod('user')],
            [PhishingResistantHardware::NAME, PhishingResistant::NAME, TwoFactors::NAME, SingleFactor::NAME],
        ];
        yield 'a credential that proves a presence and no factor' => [
            [new AuthenticationMethod('user')],
            [SingleFactor::NAME],
        ];
        yield 'a method of an upstream provider that proves no factor of its own' => [
            [new AuthenticationMethod('wia')],
            [SingleFactor::NAME],
        ];
    }

    /**
     * @return iterable<string, array{list<AuthenticationMethod>, list<string>}>
     */
    public static function provideMethodsAndThePredicatesTheySatisfy(): iterable
    {
        yield 'nothing proven' => [[], []];
        yield 'a password' => [
            [AuthenticationMethod::password()],
            [SingleFactor::NAME],
        ];
        yield 'a one-time password alone' => [[new AuthenticationMethod('otp')], [SingleFactor::NAME]];
        yield 'a presence check alone' => [[new AuthenticationMethod('user')], [SingleFactor::NAME]];
        yield 'a password and a PIN, one kind' => [
            [AuthenticationMethod::password(), new AuthenticationMethod('pin')],
            [SingleFactor::NAME],
        ];
        yield 'a password and a one-time password' => [
            [AuthenticationMethod::password(), new AuthenticationMethod('otp')],
            [TwoFactors::NAME, SingleFactor::NAME],
        ];
        yield 'a password and a fingerprint' => [
            [AuthenticationMethod::password(), new AuthenticationMethod('fpt')],
            [TwoFactors::NAME, SingleFactor::NAME],
        ];
        yield 'mfa asserted upstream' => [
            [new AuthenticationMethod('mfa')],
            [TwoFactors::NAME, SingleFactor::NAME],
        ];
        yield 'a software key alone' => [
            [new AuthenticationMethod('swk')],
            [PhishingResistant::NAME, SingleFactor::NAME],
        ];
        yield 'a hardware key alone' => [
            [new AuthenticationMethod('hwk')],
            [PhishingResistantHardware::NAME, PhishingResistant::NAME, SingleFactor::NAME],
        ];
        yield 'a password and a hardware key' => [
            [AuthenticationMethod::password(), new AuthenticationMethod('hwk')],
            [PhishingResistantHardware::NAME, PhishingResistant::NAME, TwoFactors::NAME, SingleFactor::NAME],
        ];
    }
}
