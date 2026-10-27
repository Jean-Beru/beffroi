<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Session;

use Beffroi\Core\Domain\Session\AuthenticationFactor;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use function str_repeat;

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

    /**
     * The shape a value is held to, whoever sent it: a letter or a digit, then at most sixty-three
     * letters, digits, dots, underscores, colons or hyphens.
     */
    #[Test]
    #[DataProvider('provideValuesThatAreNotWellFormed')]
    public function aValueThatIsNotWellFormedIsRefused(string $value): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs(sprintf('"%s" is not a well-formed authentication method reference.', $value));

        // When
        new AuthenticationMethod($value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideValuesThatAreNotWellFormed(): iterable
    {
        yield 'empty' => [''];
        yield 'a leading dot' => ['.pwd'];
        yield 'a space' => ['p wd'];
        yield 'longer than sixty-four characters' => [str_repeat('a', 65)];
        yield 'a line feed behind a value that would pass' => ["pwd\n"];
    }
}
