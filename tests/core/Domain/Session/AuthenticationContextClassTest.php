<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Domain\Session;

use Heidi\Core\Domain\Session\AuthenticationContextClass;
use Heidi\Core\Domain\Session\AuthenticationMethod;
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
     * OIDC Discovery §3 "acr_values_supported": what the provider can assert, the single factor today.
     */
    #[Test]
    public function theProviderAssertsTheSingleFactorClassOnly(): void
    {
        // When / Then
        static::assertSame(['1'], AuthenticationContextClass::supported());
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

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideMalformedValues(): iterable
    {
        yield 'empty' => [''];
        yield 'with a space' => ['level 1'];
        yield 'not ASCII' => ['niveau·1'];
        yield 'too long' => [str_repeat('a', 256)];
    }

    #[Test]
    public function twoClassesAreEqualByValue(): void
    {
        // When / Then
        static::assertTrue(new AuthenticationContextClass('1')->equals(new AuthenticationContextClass('1')));
        static::assertFalse(new AuthenticationContextClass('1')->equals(new AuthenticationContextClass('2')));
    }
}
