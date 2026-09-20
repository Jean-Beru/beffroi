<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Domain\Session;

use function array_map;
use Heidi\Core\Domain\Session\AuthenticationContextClass;
use Heidi\Core\Domain\Session\AuthenticationContextPolicy;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Core\Domain\Session\AuthenticationPredicate;
use Heidi\Core\Domain\Session\AuthenticationProofs;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class AuthenticationContextPolicyTest extends TestCase
{
    /**
     * Decision 0010: the default policy is the fixed vocabulary that existed, strongest first.
     */
    #[Test]
    public function theDefaultPolicyNamesTheTwoEapNamesAndTheTwoKeycloakLevels(): void
    {
        // When
        $policy = AuthenticationContextPolicy::default();

        // Then
        static::assertSame(['phrh', 'phr', '2', '1'], $policy->names());
        static::assertSame(
            [AuthenticationPredicate::PhishingResistantHardware, AuthenticationPredicate::PhishingResistant, AuthenticationPredicate::TwoFactors, AuthenticationPredicate::SingleFactor],
            array_map(static fn (AuthenticationContextClass $class): AuthenticationPredicate => $class->predicate, $policy->classes),
        );
    }

    /**
     * Decision 0010: when nothing is requested, the first class of the policy the proofs satisfy; the
     * order of declaration serves that and nothing else.
     */
    #[Test]
    #[DataProvider('provideProofsAndTheirClassUnderTheDefaultPolicy')]
    public function theClassOfProofsIsTheFirstOfThePolicyTheySatisfy(AuthenticationProofs $proofs, string $class): void
    {
        // When / Then
        static::assertSame($class, AuthenticationContextPolicy::default()->classOf($proofs)->value);
    }

    /**
     * @return iterable<string, array{AuthenticationProofs, string}>
     */
    public static function provideProofsAndTheirClassUnderTheDefaultPolicy(): iterable
    {
        $now = Fixtures::now();
        yield 'a password' => [AuthenticationProofs::of(AuthenticationMethod::password(), $now), '1'];
        yield 'a password and a one-time password' => [AuthenticationProofs::of(AuthenticationMethod::password(), $now)->with(new AuthenticationMethod('otp'), $now), '2'];
        yield 'a software key' => [AuthenticationProofs::of(new AuthenticationMethod('swk'), $now), 'phr'];
        yield 'a hardware key' => [AuthenticationProofs::of(new AuthenticationMethod('hwk'), $now), 'phrh'];
        yield 'a password and a hardware key' => [AuthenticationProofs::of(AuthenticationMethod::password(), $now)->with(new AuthenticationMethod('hwk'), $now), 'phrh'];
    }

    /**
     * A tenant that orders its policy the other way answers the weakest name first: no hierarchy is
     * assumed, the order is the tenant's.
     */
    #[Test]
    public function theOrderOfThePolicyIsTheTenantsNotAHierarchy(): void
    {
        // Given
        $policy = new AuthenticationContextPolicy([AuthenticationContextClass::singleFactor(), AuthenticationContextClass::phishingResistant()]);

        // When
        $class = $policy->classOf(AuthenticationProofs::of(new AuthenticationMethod('hwk'), Fixtures::now()));

        // Then
        static::assertSame('1', $class->value);
    }

    /**
     * Decision 0010: several names may carry the same predicate, for the vocabularies of several kinds of RP.
     */
    #[Test]
    public function aNameOfTheTenantIsFoundWithItsPredicate(): void
    {
        // Given
        $policy = new AuthenticationContextPolicy([
            new AuthenticationContextClass('urn:okta:loa:2fa:any', AuthenticationPredicate::TwoFactors),
            AuthenticationContextClass::twoFactors(),
            AuthenticationContextClass::singleFactor(),
        ]);

        // When
        $class = $policy->named('urn:okta:loa:2fa:any');

        // Then
        static::assertNotNull($class);
        static::assertSame(AuthenticationPredicate::TwoFactors, $class->predicate);
    }

    /**
     * OIDC Core §2: a name the tenant did not declare is never asserted.
     */
    #[Test]
    public function aNameTheTenantDidNotDeclareIsNoClass(): void
    {
        // When / Then
        static::assertNull(AuthenticationContextPolicy::default()->named('urn:mace:incommon:iap:silver'));
    }

    /**
     * OIDC Discovery §3 "acr_values_supported", decision 0010: the classes a login proving these methods
     * satisfies, in the order of the policy.
     *
     * @param non-empty-list<string> $methods
     * @param list<string> $provable
     */
    #[Test]
    #[DataProvider('provideMethodsAndTheClassesTheyProve')]
    public function theClassesProvableWithMethodsAreThoseTheirProofsSatisfyTogether(array $methods, array $provable): void
    {
        // When
        $classes = AuthenticationContextPolicy::default()->provableWith(array_map(static fn (string $method): AuthenticationMethod => new AuthenticationMethod($method), $methods));

        // Then
        static::assertSame($provable, array_map(static fn (AuthenticationContextClass $class): string => $class->value, $classes));
    }

    /**
     * @return iterable<string, array{non-empty-list<string>, list<string>}>
     */
    public static function provideMethodsAndTheClassesTheyProve(): iterable
    {
        yield 'a password only' => [['pwd'], ['1']];
        yield 'a password and a one-time password' => [['pwd', 'otp'], ['2', '1']];
        yield 'a password and every method of a passkey' => [['pwd', 'hwk', 'swk', 'user', 'mfa'], ['phrh', 'phr', '2', '1']];
        yield 'a synced passkey only' => [['swk', 'user'], ['phr', '1']];
    }

    #[Test]
    public function twoPoliciesAreEqualWhenTheyNameTheSameClassesInTheSameOrder(): void
    {
        // When / Then
        static::assertTrue(AuthenticationContextPolicy::default()->equals(AuthenticationContextPolicy::default()));
    }

    #[Test]
    #[DataProvider('providePoliciesThatDifferFromTheDefault')]
    public function twoPoliciesDifferByNamesPredicatesOrOrder(AuthenticationContextPolicy $other): void
    {
        // When / Then
        static::assertFalse(AuthenticationContextPolicy::default()->equals($other));
    }

    /**
     * @return iterable<string, array{AuthenticationContextPolicy}>
     */
    public static function providePoliciesThatDifferFromTheDefault(): iterable
    {
        yield 'fewer classes' => [new AuthenticationContextPolicy([AuthenticationContextClass::singleFactor()])];
        yield 'one class more' => [new AuthenticationContextPolicy([AuthenticationContextClass::phishingResistantHardware(), AuthenticationContextClass::phishingResistant(), AuthenticationContextClass::twoFactors(), AuthenticationContextClass::singleFactor(), new AuthenticationContextClass('urn:okta:loa:1fa:any', AuthenticationPredicate::SingleFactor)])];
        yield 'another order' => [new AuthenticationContextPolicy([AuthenticationContextClass::singleFactor(), AuthenticationContextClass::twoFactors(), AuthenticationContextClass::phishingResistant(), AuthenticationContextClass::phishingResistantHardware()])];
        yield 'another predicate under a name' => [new AuthenticationContextPolicy([AuthenticationContextClass::phishingResistantHardware(), AuthenticationContextClass::phishingResistant(), new AuthenticationContextClass('2', AuthenticationPredicate::PhishingResistant), AuthenticationContextClass::singleFactor()])];
    }

    /**
     * Decisions 0006 and 0010: what a policy may not say is refused when it is built, so at the start.
     *
     * @param list<AuthenticationContextClass> $classes
     */
    #[Test]
    #[DataProvider('providePoliciesRefused')]
    public function whatDecision0010ForbidsAPolicyIsRefused(array $classes, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains($message);

        // When
        new AuthenticationContextPolicy($classes);
    }

    /**
     * @return iterable<string, array{list<AuthenticationContextClass>, string}>
     */
    public static function providePoliciesRefused(): iterable
    {
        yield 'empty' => [[], 'names at least one class'];
        yield 'level 0' => [[AuthenticationContextClass::singleFactor(), new AuthenticationContextClass('0', AuthenticationPredicate::SingleFactor)], '"0" is not a class a policy may name'];
        yield 'phr on the single factor' => [[AuthenticationContextClass::singleFactor(), new AuthenticationContextClass('phr', AuthenticationPredicate::SingleFactor)], '"phr" is a registered name'];
        yield 'phr on two factors' => [[AuthenticationContextClass::singleFactor(), new AuthenticationContextClass('phr', AuthenticationPredicate::TwoFactors)], '"phr" is a registered name'];
        yield 'phrh on the phishing-resistant predicate that admits software' => [[AuthenticationContextClass::singleFactor(), new AuthenticationContextClass('phrh', AuthenticationPredicate::PhishingResistant)], '"phrh" is a registered name'];
        yield 'a name twice' => [[AuthenticationContextClass::singleFactor(), new AuthenticationContextClass('1', AuthenticationPredicate::TwoFactors)], 'names "1" once'];
        yield 'no class on the single factor' => [[AuthenticationContextClass::twoFactors(), AuthenticationContextClass::phishingResistant()], 'names a class on the single factor'];
    }

    /**
     * "phr" keeps its meaning on either phishing-resistant predicate: a hardware key is phishing resistant.
     */
    #[Test]
    public function phrMayBeNamedOnTheHardwarePredicate(): void
    {
        // When
        $policy = new AuthenticationContextPolicy([new AuthenticationContextClass('phr', AuthenticationPredicate::PhishingResistantHardware), AuthenticationContextClass::singleFactor()]);

        // Then
        static::assertSame(['phr', '1'], $policy->names());
    }
}
