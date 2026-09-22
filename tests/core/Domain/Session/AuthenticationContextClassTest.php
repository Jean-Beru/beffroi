<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Domain\Session;

use Heidi\Core\Domain\Session\AuthenticationContextClass;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Core\Domain\Session\AuthenticationPredicate;
use Heidi\Core\Domain\Session\AuthenticationProofs;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
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
        $proofs = AuthenticationProofs::of(AuthenticationMethod::password(), Fixtures::now())->with(new AuthenticationMethod('otp'), Fixtures::now());

        // When / Then
        static::assertTrue($class->isSatisfiedBy($proofs));
    }

    #[Test]
    public function aClassIsNotSatisfiedWhenItsPredicateDoesNotHold(): void
    {
        // Given
        $class = new AuthenticationContextClass('urn:okta:loa:2fa:any', AuthenticationPredicate::TwoFactors);

        // When / Then
        static::assertFalse($class->isSatisfiedBy(AuthenticationProofs::of(AuthenticationMethod::password(), Fixtures::now())));
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
    public function anAbsoluteUriOrARegisteredNameIsWellFormed(string $value): void
    {
        // When / Then
        static::assertSame($value, (string) new AuthenticationContextClass($value, AuthenticationPredicate::SingleFactor));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWellFormedValues(): iterable
    {
        yield 'level' => ['0'];
        yield 'registered name' => ['phrh'];
        yield 'URI' => ['urn:mace:incommon:iap:silver'];
        yield 'URL' => ['https://eidas.europa.eu/LoA/substantial'];
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
