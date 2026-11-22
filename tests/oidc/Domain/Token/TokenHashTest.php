<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Token;

use function hash;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Oidc\Domain\Token\TokenHash;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_match;
use function strlen;

final class TokenHashTest extends TestCase
{
    #[Test]
    public function itMatchesTheExampleOfTheSpecification(): void
    {
        // When / Then
        static::assertSame('77QmUPtjPfzWtF2AnpK9RQ', TokenHash::of('jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y', Algorithms::rs256()));
    }

    /**
     * OIDC Core §3.1.3.6
     */
    #[Test]
    public function itKeepsTheLeftHalfOfTheDigestOnly(): void
    {
        // When
        $hash = TokenHash::of('token', Algorithms::rs256());

        // Then
        static::assertSame(1, preg_match('/^[A-Za-z0-9_-]{22}$/', $hash));
        static::assertSame(32, strlen(hash('sha256', 'token', true)));
        static::assertSame('PEaenWxYddN6Q_NT1PiOYQ', $hash, 'the value is stable: the first 16 bytes of SHA-256("token")');
    }

    #[Test]
    public function twoTokensHashDifferently(): void
    {
        // When / Then
        static::assertNotSame(TokenHash::of('token', Algorithms::rs256()), TokenHash::of('token2', Algorithms::rs256()));
    }
}
