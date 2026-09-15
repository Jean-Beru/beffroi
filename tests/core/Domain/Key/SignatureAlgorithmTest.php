<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Domain\Key;

use Heidi\Core\Domain\Key\SignatureAlgorithm;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class SignatureAlgorithmTest extends TestCase
{
    /**
     * RFC 7518 §3.3: RS256 is RSASSA-PKCS1-v1_5 with SHA-256 over RSA keys of 2048 bits at least.
     */
    #[Test]
    public function rs256IsRsaWithSha256(): void
    {
        // When / Then
        static::assertSame('RSA', SignatureAlgorithm::RS256->keyType());
        static::assertSame(2048, SignatureAlgorithm::RS256->minimumKeyBits());
        static::assertSame('sha256', SignatureAlgorithm::RS256->digestAlgorithm());
    }
}
