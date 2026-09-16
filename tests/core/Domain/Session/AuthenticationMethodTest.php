<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Domain\Session;

use Heidi\Core\Domain\Session\AuthenticationFactor;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class AuthenticationMethodTest extends TestCase
{
    /**
     * RFC 8176 §2: each registered method proves something the user knows, has or is.
     */
    #[Test]
    #[DataProvider('provideMethodsAndTheirFactor')]
    public function aRegisteredMethodProvesOneKindOfFactor(string $method, AuthenticationFactor $factor): void
    {
        // When / Then
        static::assertSame($factor, new AuthenticationMethod($method)->factor());
    }

    /**
     * @return iterable<string, array{string, AuthenticationFactor}>
     */
    public static function provideMethodsAndTheirFactor(): iterable
    {
        yield 'password' => ['pwd', AuthenticationFactor::Knowledge];
        yield 'PIN' => ['pin', AuthenticationFactor::Knowledge];
        yield 'knowledge-based' => ['kba', AuthenticationFactor::Knowledge];
        yield 'one-time password' => ['otp', AuthenticationFactor::Possession];
        yield 'hardware key' => ['hwk', AuthenticationFactor::Possession];
        yield 'software key' => ['swk', AuthenticationFactor::Possession];
        yield 'smart card' => ['sc', AuthenticationFactor::Possession];
        yield 'SMS' => ['sms', AuthenticationFactor::Possession];
        yield 'telephone' => ['tel', AuthenticationFactor::Possession];
        yield 'proof of possession' => ['pop', AuthenticationFactor::Possession];
        yield 'face' => ['face', AuthenticationFactor::Inherence];
        yield 'fingerprint' => ['fpt', AuthenticationFactor::Inherence];
        yield 'iris' => ['iris', AuthenticationFactor::Inherence];
        yield 'retina' => ['retina', AuthenticationFactor::Inherence];
        yield 'voice' => ['vbm', AuthenticationFactor::Inherence];
    }

    /**
     * RFC 8176 §2: a presence check, a location, a risk score, a channel or a provider's own value
     * describes a proof without being a factor.
     */
    #[Test]
    #[DataProvider('provideMethodsWithoutAFactor')]
    public function whatIsNotAFactorProvesNone(string $method): void
    {
        // When / Then
        static::assertNull(new AuthenticationMethod($method)->factor());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideMethodsWithoutAFactor(): iterable
    {
        yield 'user presence' => ['user'];
        yield 'geolocation' => ['geo'];
        yield 'risk-based' => ['rba'];
        yield 'multiple channels' => ['mca'];
        yield 'Windows integrated' => ['wia'];
        yield 'multiple factors, unnamed' => ['mfa'];
        yield 'a value of the provider' => ['x-badge'];
    }

    /**
     * RFC 8176 §2 "mfa": several factors asserted without naming each.
     */
    #[Test]
    public function mfaAssertsMultipleFactors(): void
    {
        // When / Then
        static::assertTrue(new AuthenticationMethod('mfa')->isMultipleFactors());
        static::assertFalse(AuthenticationMethod::password()->isMultipleFactors());
    }
}
