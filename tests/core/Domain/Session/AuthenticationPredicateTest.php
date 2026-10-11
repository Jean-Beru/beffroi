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
 * The predicates of decision 0010, each a class the provider is wired with (issue #607): what every one
 * of them answers of the same proofs, read off the wiring and never off an enumeration of kinds.
 */
final class AuthenticationPredicateTest extends TestCase
{
    /**
     * OIDC Core §5.5.1.1, architecture §3.2, decision 0010: a predicate reads which methods were proven,
     * every predicate that holds holds, not only the strongest; a factor is the kind RFC 8176 §2 gives a
     * method. When a method was proven is no business of a predicate, so none of these cases dates one.
     *
     * @param list<AuthenticationMethod> $methods
     * @param list<string> $satisfied the predicates that hold, by the name each gives itself
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
     * Decision 0025: a tenant names a predicate as the floor of its logins, and what may be enrolled there
     * is read off it, kind by kind, from what one authentication with that kind would prove. A floor admits
     * a credential when it reads one of those methods: under the two factors a password is half of what
     * meets it, where under a phishing-resistant floor it is never part of anything that does.
     *
     * @param list<AuthenticationMethod> $methods
     * @param list<string> $admitting the floors that admit the credential, by the name each gives itself
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
     * Architecture §4.6: every session has an "acr", so a policy is built on a predicate that holds as
     * soon as anything at all was proven, and the provider knows which of its predicates are one without
     * reading their names (AuthenticationContextPolicy). Of the four wired, the single factor is the one.
     */
    #[Test]
    public function theSingleFactorIsTheOnePredicateThatHoldsOnEveryLogin(): void
    {
        // When / Then
        foreach (Predicates::all() as $predicate) {
            static::assertSame($predicate->name() === SingleFactor::NAME, $predicate->holdsOnEveryLogin(), $predicate->name());
        }
    }

    /**
     * A predicate is resolved by the name it gives itself, here and in the configuration of a tenant, in a
     * stored policy and in a stored floor (WiredAuthenticationPredicates).
     */
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
