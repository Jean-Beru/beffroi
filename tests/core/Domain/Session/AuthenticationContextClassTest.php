<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Domain\Session;

use Heidi\Core\Domain\Session\AuthenticationContextClass;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Core\Domain\Session\AuthenticationProofs;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Tests\Fixture\Fixtures;
use function in_array;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

final class AuthenticationContextClassTest extends TestCase
{
    /**
     * OIDC Core §2, architecture §3.2: a password proves one factor, the class is "1".
     */
    #[Test]
    public function aPasswordProofSatisfiesTheSingleFactorClass(): void
    {
        // Given
        $proofs = AuthenticationProofs::of(AuthenticationMethod::password(), Fixtures::now());

        // When
        $class = AuthenticationContextClass::of($proofs);

        // Then
        static::assertSame('1', $class->value);
        static::assertTrue($class->equals(AuthenticationContextClass::singleFactor()));
    }

    /**
     * Architecture §3.2: the strongest class the proofs satisfy, "phrh" above "phr" above "2" above "1".
     */
    #[Test]
    #[DataProvider('provideProofsAndTheirStrongestClass')]
    public function theClassOfASessionIsTheStrongestItsProofsSatisfy(AuthenticationProofs $proofs, string $class): void
    {
        // When / Then
        static::assertSame($class, AuthenticationContextClass::of($proofs)->value);
    }

    /**
     * @return iterable<string, array{AuthenticationProofs, string}>
     */
    public static function provideProofsAndTheirStrongestClass(): iterable
    {
        $now = Fixtures::now();
        yield 'a one-time password alone' => [AuthenticationProofs::of(new AuthenticationMethod('otp'), $now), '1'];
        yield 'a password and a PIN, one kind' => [AuthenticationProofs::of(AuthenticationMethod::password(), $now)->with(new AuthenticationMethod('pin'), $now), '1'];
        yield 'a password and a one-time password' => [AuthenticationProofs::of(AuthenticationMethod::password(), $now)->with(new AuthenticationMethod('otp'), $now), '2'];
        yield 'a password and a fingerprint' => [AuthenticationProofs::of(AuthenticationMethod::password(), $now)->with(new AuthenticationMethod('fpt'), $now), '2'];
        yield 'mfa asserted upstream' => [AuthenticationProofs::of(new AuthenticationMethod('mfa'), $now), '2'];
        yield 'a software key' => [AuthenticationProofs::of(new AuthenticationMethod('swk'), $now), 'phr'];
        yield 'a hardware key' => [AuthenticationProofs::of(new AuthenticationMethod('hwk'), $now), 'phrh'];
        yield 'a password and a hardware key' => [AuthenticationProofs::of(AuthenticationMethod::password(), $now)->with(new AuthenticationMethod('hwk'), $now), 'phrh'];
        yield 'a presence check alone' => [AuthenticationProofs::of(new AuthenticationMethod('user'), $now), '1'];
    }

    /**
     * OIDC Core §5.5.1.1, architecture §3.2: a class is a predicate on the proofs, and a session
     * satisfies every class whose predicate holds, not only the strongest.
     *
     * @param list<string> $satisfied
     */
    #[Test]
    #[DataProvider('provideProofsAndTheClassesTheySatisfy')]
    public function aSessionSatisfiesEveryClassWhosePredicateHolds(AuthenticationProofs $proofs, array $satisfied): void
    {
        // When / Then
        foreach (['1', '2', 'phr', 'phrh'] as $value) {
            static::assertSame(in_array($value, $satisfied, true), new AuthenticationContextClass($value)->isSatisfiedBy($proofs), $value);
        }
    }

    /**
     * @return iterable<string, array{AuthenticationProofs, list<string>}>
     */
    public static function provideProofsAndTheClassesTheySatisfy(): iterable
    {
        $now = Fixtures::now();
        yield 'a password' => [AuthenticationProofs::of(AuthenticationMethod::password(), $now), ['1']];
        yield 'a password and a one-time password' => [AuthenticationProofs::of(AuthenticationMethod::password(), $now)->with(new AuthenticationMethod('otp'), $now), ['1', '2']];
        yield 'a software key alone' => [AuthenticationProofs::of(new AuthenticationMethod('swk'), $now), ['1', 'phr']];
        yield 'a hardware key alone' => [AuthenticationProofs::of(new AuthenticationMethod('hwk'), $now), ['1', 'phr', 'phrh']];
        yield 'a password and a hardware key' => [AuthenticationProofs::of(AuthenticationMethod::password(), $now)->with(new AuthenticationMethod('hwk'), $now), ['1', '2', 'phr', 'phrh']];
    }

    /**
     * OIDC Core §2: the provider asserts nothing it has not defined; a name of RFC 6711 or a URI of a
     * federation is never satisfied, whatever the proofs.
     */
    #[Test]
    #[DataProvider('provideClassesTheProviderDoesNotDefine')]
    public function aClassTheProviderDoesNotDefineIsNeverSatisfied(string $value): void
    {
        // Given
        $proofs = AuthenticationProofs::of(AuthenticationMethod::password(), Fixtures::now())->with(new AuthenticationMethod('hwk'), Fixtures::now());

        // When / Then
        static::assertFalse(new AuthenticationContextClass($value)->isSatisfiedBy($proofs));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideClassesTheProviderDoesNotDefine(): iterable
    {
        yield 'level 0' => ['0'];
        yield 'level 3' => ['3'];
        yield 'a registered name' => ['urn:mace:incommon:iap:silver'];
        yield 'a URL' => ['https://eidas.europa.eu/LoA/substantial'];
    }

    /**
     * OIDC Discovery §3 "acr_values_supported": what a credential of the provider can prove, the single
     * factor while the password is the only credential.
     */
    #[Test]
    public function theProviderAssertsTheSingleFactorClassOnly(): void
    {
        // When / Then
        static::assertSame(['1'], AuthenticationContextClass::supported());
    }

    #[Test]
    public function eachDefinedClassHasItsConstructor(): void
    {
        // When / Then
        static::assertSame('1', AuthenticationContextClass::singleFactor()->value);
        static::assertSame('2', AuthenticationContextClass::twoFactors()->value);
        static::assertSame('phr', AuthenticationContextClass::phishingResistant()->value);
        static::assertSame('phrh', AuthenticationContextClass::phishingResistantHardware()->value);
    }

    #[Test]
    #[DataProvider('provideWellFormedValues')]
    public function anAbsoluteUriOrARegisteredNameIsWellFormed(string $value): void
    {
        // When / Then
        static::assertSame($value, (string) new AuthenticationContextClass($value));
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
        new AuthenticationContextClass($value);
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

    #[Test]
    public function twoClassesAreEqualByValue(): void
    {
        // When / Then
        static::assertTrue(new AuthenticationContextClass('1')->equals(new AuthenticationContextClass('1')));
        static::assertFalse(new AuthenticationContextClass('1')->equals(new AuthenticationContextClass('2')));
    }
}
