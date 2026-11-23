<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Key;

use Beffroi\Core\Domain\Key\RsaModulus;
use Beffroi\Core\Tests\Fixture\Keys;
use Beffroi\Core\Tests\Fixture\RsaModuli;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7518 §6.3.1.1
 */
final class RsaModulusTest extends TestCase
{
    #[Test]
    #[DataProvider('provideModuli')]
    public function itCountsTheBitsOfAModulus(string $n, int $bits): void
    {
        // When / Then
        static::assertSame($bits, RsaModulus::bitsOf($n));
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function provideModuli(): iterable
    {
        yield '2048 bits' => [RsaModuli::ofBits(2048), 2048];
        yield '2047 bits' => [RsaModuli::ofBits(2047), 2047];
        yield '2049 bits' => [RsaModuli::ofBits(2049), 2049];
        yield '1 bit' => [RsaModuli::ofBits(1), 1];
        yield '2048 bits behind a zero octet' => [RsaModuli::ofBits(2048, 1), 2048];
        yield '2047 bits behind two zero octets' => [RsaModuli::ofBits(2047, 2), 2047];
        yield 'zero octets only' => ['AAAA', 0];
        yield 'no octet' => ['', 0];
    }

    #[Test]
    public function itCountsTheBitsOfAKeyTheProviderGenerated(): void
    {
        // Given
        $n = Keys::pair()->publicJwk['n'] ?? static::fail('The key of the provider carries no modulus.');

        // When / Then
        static::assertSame(2048, RsaModulus::bitsOf($n));
    }

    #[Test]
    #[DataProvider('provideWhatIsNotBase64url')]
    public function itCountsNothingInWhatIsNotBase64url(string $n): void
    {
        // When / Then
        static::assertNull(RsaModulus::bitsOf($n));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWhatIsNotBase64url(): iterable
    {
        yield 'the alphabet of standard base64' => ['ab+/cd'];
        yield 'padding' => ['AQAB=='];
        yield 'a character of neither alphabet' => ['AQ!B'];
        yield 'a length no octets have' => ['A'];
    }
}
