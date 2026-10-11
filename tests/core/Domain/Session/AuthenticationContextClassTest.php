<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Session;

use Beffroi\Core\Domain\Session\AuthenticationContextClass;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\AuthenticationPredicate;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use function str_repeat;

final class AuthenticationContextClassTest extends TestCase
{
    /**
     * Decision 0010: a class is a name on a predicate of the provider; it is satisfied when its predicate is.
     */
    #[Test]
    public function aClassIsSatisfiedWhenItsPredicateHolds(): void
    {
        // Given
        $class = new AuthenticationContextClass('urn:okta:loa:2fa:any', AuthenticationPredicate::TwoFactors);
        $methods = [AuthenticationMethod::password(), new AuthenticationMethod('otp')];

        // When / Then
        static::assertTrue($class->isSatisfiedBy($methods));
    }

    #[Test]
    public function aClassIsNotSatisfiedWhenItsPredicateDoesNotHold(): void
    {
        // Given
        $class = new AuthenticationContextClass('urn:okta:loa:2fa:any', AuthenticationPredicate::TwoFactors);

        // When / Then
        static::assertFalse($class->isSatisfiedBy([AuthenticationMethod::password()]));
    }

    /**
     * The four classes of the default policy, each on its predicate.
     */
    #[Test]
    #[DataProvider('provideDefaultClasses')]
    public function eachClassOfTheDefaultPolicyHasItsConstructor(AuthenticationContextClass $class, string $value, AuthenticationPredicate $predicate): void
    {
        // When / Then
        static::assertSame($value, $class->value);
        static::assertSame($predicate, $class->predicate);
    }

    /**
     * @return iterable<string, array{AuthenticationContextClass, string, AuthenticationPredicate}>
     */
    public static function provideDefaultClasses(): iterable
    {
        yield 'the single factor' => [AuthenticationContextClass::singleFactor(), '1', AuthenticationPredicate::SingleFactor];
        yield 'two factors' => [AuthenticationContextClass::twoFactors(), '2', AuthenticationPredicate::TwoFactors];
        yield 'phishing resistant' => [AuthenticationContextClass::phishingResistant(), 'phr', AuthenticationPredicate::PhishingResistant];
        yield 'phishing resistant, hardware' => [
            AuthenticationContextClass::phishingResistantHardware(),
            'phrh',
            AuthenticationPredicate::PhishingResistantHardware,
        ];
    }

    #[Test]
    #[DataProvider('provideWellFormedValues')]
    public function anAbsoluteUriOrARegisteredNameIsWellFormed(string $value, AuthenticationPredicate $predicate): void
    {
        // When / Then
        static::assertSame($value, (string) new AuthenticationContextClass($value, $predicate));
    }

    /**
     * @return iterable<string, array{string, AuthenticationPredicate}>
     */
    public static function provideWellFormedValues(): iterable
    {
        yield 'level' => ['0', AuthenticationPredicate::SingleFactor];
        yield 'registered name' => ['phrh', AuthenticationPredicate::PhishingResistantHardware];
        yield 'URI' => ['urn:mace:incommon:iap:silver', AuthenticationPredicate::SingleFactor];
        yield 'URL' => ['https://eidas.europa.eu/LoA/substantial', AuthenticationPredicate::SingleFactor];
    }

    #[Test]
    #[DataProvider('provideMalformedValues')]
    public function whatIsNotPrintableAsciiWithoutSpaceIsRefused(string $value): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('is not a well-formed authentication context class reference');

        // When
        new AuthenticationContextClass($value, AuthenticationPredicate::SingleFactor);
    }

    #[Test]
    #[DataProvider('provideMalformedValues')]
    public function whatIsNotPrintableAsciiWithoutSpaceIsNotWellFormed(string $value): void
    {
        // When / Then
        static::assertFalse(AuthenticationContextClass::isWellFormed($value));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideMalformedValues(): iterable
    {
        yield 'empty' => [''];
        yield 'with a space' => ['level 1'];
        yield 'not ASCII' => ['niveau·1'];
        yield 'too long' => [str_repeat('a', 256)];
        yield 'with a trailing newline' => ["1\n"];
    }

    /**
     * OIDC Core §2 forbids a registered name in another sense than its own, and the class is where that is
     * refused: a pairing the policy would never accept is not built either.
     */
    #[Test]
    #[DataProvider('provideRegisteredNamesOutOfTheirMeaning')]
    public function aRegisteredNameIsRefusedOnAPredicateThatIsNotItsMeaning(string $value, AuthenticationPredicate $predicate): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs(sprintf(
            '"%s" is a registered name (OpenID Connect EAP ACR Values 1.0) and keeps its meaning: it cannot be named on the "%s" predicate.',
            $value,
            $predicate->value,
        ));

        // When
        new AuthenticationContextClass($value, $predicate);
    }

    /**
     * @return iterable<string, array{string, AuthenticationPredicate}>
     */
    public static function provideRegisteredNamesOutOfTheirMeaning(): iterable
    {
        yield 'phr on the single factor' => ['phr', AuthenticationPredicate::SingleFactor];
        yield 'phr on two factors' => ['phr', AuthenticationPredicate::TwoFactors];
        yield 'phrh on the phishing-resistant predicate that admits software' => ['phrh', AuthenticationPredicate::PhishingResistant];
    }

    /**
     * "phr" keeps its meaning on either phishing-resistant predicate: a hardware key is phishing resistant.
     */
    #[Test]
    public function phrMayBeNamedOnTheHardwarePredicate(): void
    {
        // When
        $class = new AuthenticationContextClass('phr', AuthenticationPredicate::PhishingResistantHardware);

        // Then
        static::assertSame(AuthenticationPredicate::PhishingResistantHardware, $class->predicate);
    }

    /**
     * A policy names each class once: the name is the identity.
     */
    #[Test]
    public function twoClassesAreEqualByName(): void
    {
        // When / Then
        static::assertTrue(new AuthenticationContextClass('1', AuthenticationPredicate::SingleFactor)->equals(new AuthenticationContextClass(
            '1',
            AuthenticationPredicate::TwoFactors,
        )));
        static::assertFalse(new AuthenticationContextClass('1', AuthenticationPredicate::SingleFactor)->equals(new AuthenticationContextClass(
            '2',
            AuthenticationPredicate::SingleFactor,
        )));
    }
}
