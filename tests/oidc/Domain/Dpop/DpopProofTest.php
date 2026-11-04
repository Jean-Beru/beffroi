<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Dpop;

use Beffroi\Oidc\Domain\Dpop\DpopProof;
use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use Beffroi\Oidc\Exception\InvalidDpopProofException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 9449 §4.2
 */
final class DpopProofTest extends TestCase
{
    #[Test]
    public function itReadsTheClaimsOfTheSpecification(): void
    {
        // Given
        $proof = self::proof([
            'jti' => 'the-proof',
            'htm' => 'POST',
            'htu' => 'https://id.acme.example/token',
            'iat' => 1758542400,
            'ath' => 'fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo',
            'nonce' => 'the-nonce',
        ]);

        // When / Then
        static::assertSame('the-proof', $proof->identifier());
        static::assertSame('POST', $proof->method());
        static::assertSame('https://id.acme.example/token', $proof->url());
        static::assertSame(1758542400, $proof->issuedAt()->getTimestamp());
        static::assertSame('fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo', $proof->accessTokenHash());
        static::assertSame('the-nonce', $proof->nonce());
    }

    #[Test]
    public function whatAProofDoesNotCarryIsNotRead(): void
    {
        // Given
        $proof = self::proof([
            'jti' => 'the-proof',
        ]);

        // When / Then
        static::assertNull($proof->accessTokenHash());
        static::assertNull($proof->nonce());
    }

    /**
     * RFC 9110 §9.1
     */
    #[Test]
    public function aMethodThatIsNotOneIsRefused(): void
    {
        // Given
        $proof = self::proof([
            'htm' => 'POST /token',
        ]);

        // Then
        $this->expectException(InvalidDpopProofException::class);
        $this->expectExceptionMessageIs('invalid_dpop_proof: The htm of a DPoP proof is an HTTP method (RFC 9449 section 4.2).');

        // When
        $proof->method();
    }

    #[Test]
    #[DataProvider('provideUnreadableClaims')]
    public function aClaimThatIsNotAStringIsRefused(mixed $value): void
    {
        // Given
        $proof = self::proof([
            'ath' => $value,
        ]);

        // Then
        $this->expectException(InvalidDpopProofException::class);
        $this->expectExceptionMessageIs('invalid_dpop_proof: The ath of a DPoP proof is a non-empty string (RFC 9449 section 4.2).');

        // When
        $proof->accessTokenHash();
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function provideUnreadableClaims(): iterable
    {
        yield 'a number' => [42];
        yield 'an empty string' => [''];
        yield 'a list' => [['a-hash']];
    }

    /**
     * @param array<string, mixed> $claims
     */
    private static function proof(array $claims): DpopProof
    {
        return new DpopProof(
            new UnverifiedJwt(
                'the.compact.proof',
                [
                    'typ' => DpopProof::TYPE,
                    'alg' => 'ES256',
                ],
                $claims,
            ),
        );
    }
}
