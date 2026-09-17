<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Token;

use Heidi\Oidc\Domain\Token\OpaqueTokenValue;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_match;
use function strlen;

final class OpaqueTokenValueTest extends TestCase
{
    /**
     * Architecture §4.6: 256 bits of the CSPRNG in base64url, without a dot, which is what tells an opaque
     * token from a compact JWS.
     */
    #[Test]
    public function aValueIs256RandomBitsInBase64url(): void
    {
        // When
        $value = OpaqueTokenValue::draw();

        // Then
        static::assertSame(1, preg_match('/^[A-Za-z0-9_-]{43}$/', $value));
        static::assertNotSame($value, OpaqueTokenValue::draw());
    }

    /**
     * Architecture §4.6: stored as its SHA-256.
     */
    #[Test]
    public function aValueIsHashedWithSha256(): void
    {
        // When / Then
        static::assertSame('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', OpaqueTokenValue::hash(''));
        static::assertSame(64, strlen(OpaqueTokenValue::hash(OpaqueTokenValue::draw())));
    }

    #[Test]
    public function twoValuesHashDifferently(): void
    {
        // Given
        $value = OpaqueTokenValue::draw();
        $again = OpaqueTokenValue::draw();

        // When / Then
        static::assertSame(OpaqueTokenValue::hash($value), OpaqueTokenValue::hash($value));
        static::assertNotSame(OpaqueTokenValue::hash($value), OpaqueTokenValue::hash($again));
    }
}
