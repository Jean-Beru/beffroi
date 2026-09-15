<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Token;

use function hash;
use Heidi\Core\Domain\Key\SignatureAlgorithm;
use Heidi\Oidc\Domain\Token\TokenHash;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_match;
use function strlen;

final class TokenHashTest extends TestCase
{
    /**
     * OIDC Core appendix A.3: the access token "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y" of the
     * example has the at_hash "77QmUPtjPfzWtF2AnpK9RQ" under RS256.
     */
    #[Test]
    public function itMatchesTheExampleOfTheSpecification(): void
    {
        static::assertSame('77QmUPtjPfzWtF2AnpK9RQ', TokenHash::of('jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y', SignatureAlgorithm::RS256));
    }

    /**
     * OIDC Core §3.1.3.6: the left-most 128 bits of SHA-256, so 22 base64url characters, and a different
     * value for a different token; the whole digest is not what is encoded.
     */
    #[Test]
    public function itKeepsTheLeftHalfOfTheDigestOnly(): void
    {
        $hash = TokenHash::of('token', SignatureAlgorithm::RS256);

        static::assertSame(1, preg_match('/^[A-Za-z0-9_-]{22}$/', $hash));
        static::assertSame(32, strlen(hash('sha256', 'token', true)));
        static::assertNotSame($hash, TokenHash::of('token2', SignatureAlgorithm::RS256));
        static::assertSame('PEaenWxYddN6Q_NT1PiOYQ', $hash, 'the value is stable: the first 16 bytes of SHA-256("token")');
    }
}
