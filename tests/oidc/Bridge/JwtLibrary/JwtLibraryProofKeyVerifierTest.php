<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Bridge\JwtLibrary;

use DateTimeImmutable;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Oidc\Bridge\JwtLibrary\JwtLibraryCompactJwtReader;
use Beffroi\Oidc\Bridge\JwtLibrary\JwtLibraryProofKeyVerifier;
use Beffroi\Oidc\Domain\Dpop\DpopProof;
use Beffroi\Oidc\Domain\Token\KeyConfirmation;
use Beffroi\Oidc\Exception\InvalidJwtException;
use Beffroi\Oidc\Tests\Fixture\Proofs;
use Jose\Component\Core\JWK;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 9449 §4.3, RFC 7638 §3
 */
final class JwtLibraryProofKeyVerifierTest extends TestCase
{
    private const string NOW = '2026-09-22T12:00:00+00:00';

    private const string ENDPOINT = 'https://id.acme.example/token';

    /**
     * RFC 7638 §3.1
     */
    #[Test]
    public function theThumbprintIsTheOneTheSpecificationPublishes(): void
    {
        // Given
        $key = new JWK([
            'kty' => 'RSA',
            'n' => '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
            'e' => 'AQAB',
            'alg' => 'RS256',
            'kid' => '2011-04-29',
        ]);

        // When
        $confirmation = new KeyConfirmation($key->thumbprint('sha256'));

        // Then
        static::assertSame('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs', $confirmation->thumbprint);
    }

    #[Test]
    public function itAnswersTheThumbprintOfTheKeyThatSigned(): void
    {
        // Given
        $proof = new JwtLibraryCompactJwtReader()->read(Proofs::proof('POST', self::ENDPOINT, new DateTimeImmutable(self::NOW)));

        // When
        $thumbprint = self::verifier()->keyThatSigned($proof, ['ES256']);

        // Then
        static::assertSame(Proofs::key()->toPublic()->thumbprint('sha256'), $thumbprint);
    }

    /**
     * RFC 8725 §3.1
     */
    #[Test]
    public function aProofSignedWithAnAlgorithmTheProviderDoesNotTakeIsRefused(): void
    {
        // Given
        $proof = new JwtLibraryCompactJwtReader()->read(Proofs::proof('POST', self::ENDPOINT, new DateTimeImmutable(self::NOW)));

        // Then
        $this->expectException(InvalidJwtException::class);
        $this->expectExceptionMessageIs('The proof is signed with "ES256", which this provider does not take.');

        // When
        self::verifier()->keyThatSigned($proof, ['RS256']);
    }

    /**
     * RFC 7517 §4.1
     */
    #[Test]
    public function aProofWhoseKeyNamesNoKeyTypeIsRefused(): void
    {
        // Given
        $key = Proofs::key()->toPublic()->all();
        unset($key['kty']);
        $proof = new JwtLibraryCompactJwtReader()->read(Proofs::proof('POST', self::ENDPOINT, new DateTimeImmutable(self::NOW), header: [
            DpopProof::KEY => $key,
        ]));

        // Then
        $this->expectException(InvalidJwtException::class);
        $this->expectExceptionMessageIs('The signature of the token cannot be checked under the key.');

        // When
        self::verifier()->keyThatSigned($proof, ['ES256']);
    }

    private static function verifier(): JwtLibraryProofKeyVerifier
    {
        return new JwtLibraryProofKeyVerifier(Algorithms::all()->manager());
    }
}
