<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Session;

use Beffroi\Core\Domain\Session\AuthenticationContextClass;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\AuthenticationPredicateInterface;
use Beffroi\Core\Domain\Session\PhishingResistant;
use Beffroi\Core\Domain\Session\PhishingResistantHardware;
use Beffroi\Core\Domain\Session\SingleFactor;
use Beffroi\Core\Domain\Session\TwoFactors;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use function str_repeat;

final class AuthenticationContextClassTest extends TestCase
{
    /**
     * Decision 0010
     */
    #[Test]
    public function aClassIsSatisfiedWhenItsPredicateHolds(): void
    {
        // Given
        $class = new AuthenticationContextClass('urn:okta:loa:2fa:any', new TwoFactors());
        $methods = [AuthenticationMethod::password(), new AuthenticationMethod('otp')];

        // When / Then
        static::assertTrue($class->isSatisfiedBy($methods));
    }

    #[Test]
    public function aClassIsNotSatisfiedWhenItsPredicateDoesNotHold(): void
    {
        // Given
        $class = new AuthenticationContextClass('urn:okta:loa:2fa:any', new TwoFactors());

        // When / Then
        static::assertFalse($class->isSatisfiedBy([AuthenticationMethod::password()]));
    }

    #[Test]
    #[DataProvider('provideDefaultClasses')]
    public function eachClassOfTheDefaultPolicyHasItsConstructor(AuthenticationContextClass $class, string $value, string $predicate): void
    {
        // When / Then
        static::assertSame($value, $class->value);
        static::assertSame($predicate, $class->predicate->name());
    }

    /**
     * @return iterable<string, array{AuthenticationContextClass, string, string}>
     */
    public static function provideDefaultClasses(): iterable
    {
        yield 'the single factor' => [AuthenticationContextClass::singleFactor(), '1', SingleFactor::NAME];
        yield 'two factors' => [AuthenticationContextClass::twoFactors(), '2', TwoFactors::NAME];
        yield 'phishing resistant' => [AuthenticationContextClass::phishingResistant(), 'phr', PhishingResistant::NAME];
        yield 'phishing resistant, hardware' => [
            AuthenticationContextClass::phishingResistantHardware(),
            'phrh',
            PhishingResistantHardware::NAME,
        ];
    }

    #[Test]
    #[DataProvider('provideWellFormedValues')]
    public function anAbsoluteUriOrARegisteredNameIsWellFormed(string $value, AuthenticationPredicateInterface $predicate): void
    {
        // When / Then
        static::assertSame($value, (string) new AuthenticationContextClass($value, $predicate));
    }

    /**
     * @return iterable<string, array{string, AuthenticationPredicateInterface}>
     */
    public static function provideWellFormedValues(): iterable
    {
        yield 'level' => ['0', new SingleFactor()];
        yield 'registered name' => ['phrh', new PhishingResistantHardware()];
        yield 'URI' => ['urn:mace:incommon:iap:silver', new SingleFactor()];
        yield 'URL' => ['https://eidas.europa.eu/LoA/substantial', new SingleFactor()];
    }

    #[Test]
    #[DataProvider('provideMalformedValues')]
    public function whatIsNotPrintableAsciiWithoutSpaceIsRefused(string $value): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('is not a well-formed authentication context class reference');

        // When
        new AuthenticationContextClass($value, new SingleFactor());
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
     * OIDC Core §2
     */
    #[Test]
    #[DataProvider('provideRegisteredNamesOutOfTheirMeaning')]
    public function aRegisteredNameIsRefusedOnAPredicateThatIsNotItsMeaning(string $value, AuthenticationPredicateInterface $predicate): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs(sprintf(
            '"%s" is a registered name (OpenID Connect EAP ACR Values 1.0) and keeps its meaning: it cannot be named on the "%s" predicate.',
            $value,
            $predicate->name(),
        ));

        // When
        new AuthenticationContextClass($value, $predicate);
    }

    /**
     * @return iterable<string, array{string, AuthenticationPredicateInterface}>
     */
    public static function provideRegisteredNamesOutOfTheirMeaning(): iterable
    {
        yield 'phr on the single factor' => ['phr', new SingleFactor()];
        yield 'phr on two factors' => ['phr', new TwoFactors()];
        yield 'phrh on the phishing-resistant predicate that admits software' => ['phrh', new PhishingResistant()];
    }

    #[Test]
    public function phrMayBeNamedOnTheHardwarePredicate(): void
    {
        // When
        $class = new AuthenticationContextClass('phr', new PhishingResistantHardware());

        // Then
        static::assertSame(PhishingResistantHardware::NAME, $class->predicate->name());
    }

    #[Test]
    public function twoClassesAreEqualByName(): void
    {
        // When / Then
        static::assertTrue(new AuthenticationContextClass('1', new SingleFactor())->equals(new AuthenticationContextClass(
            '1',
            new TwoFactors(),
        )));
        static::assertFalse(new AuthenticationContextClass('1', new SingleFactor())->equals(new AuthenticationContextClass(
            '2',
            new SingleFactor(),
        )));
    }
}
