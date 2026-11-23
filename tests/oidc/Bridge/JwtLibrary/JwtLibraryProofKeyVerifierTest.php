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
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use function json_encode;
use const JSON_THROW_ON_ERROR;
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

    /**
     * RFC 7518 §3.3
     */
    #[Test]
    public function aProofSignedByAnRsaKeyOf2048BitsIsVerified(): void
    {
        // Given
        $key = JWKFactory::createRSAKey(2048);
        $proof = new JwtLibraryCompactJwtReader()->read(self::rs256Proof($key));

        // When
        $thumbprint = self::verifier()->keyThatSigned($proof, ['RS256']);

        // Then
        static::assertSame($key->toPublic()->thumbprint('sha256'), $thumbprint);
    }

    /**
     * RFC 7518 §3.3, RFC 9449 §4.3
     */
    #[Test]
    public function aProofSignedByAnRsaKeyOfLessThan2048BitsIsRefused(): void
    {
        // Given
        $proof = new JwtLibraryCompactJwtReader()->read(self::rs256Proof(JWKFactory::createRSAKey(1024)));

        // Then
        $this->expectException(InvalidJwtException::class);
        $this->expectExceptionMessageIs('The RSA key the proof carries has a modulus "n" of 2048 bits at least (RFC 7518 sections 3.3 and 3.5).');

        // When
        self::verifier()->keyThatSigned($proof, ['RS256']);
    }

    private static function rs256Proof(JWK $key): string
    {
        $jws = new JWSBuilder(new AlgorithmManager([Algorithms::rs256()->joseAlgorithm()]))
            ->create()
            ->withPayload(json_encode([
                'jti' => 'proof',
                'htm' => 'POST',
                'htu' => self::ENDPOINT,
                'iat' => new DateTimeImmutable(self::NOW)->getTimestamp(),
            ], JSON_THROW_ON_ERROR))
            ->addSignature($key, [
                'alg' => 'RS256',
                'typ' => DpopProof::TYPE,
                DpopProof::KEY => $key->toPublic()->all(),
            ])
            ->build();

        return new CompactSerializer()->serialize($jws, 0);
    }

    private static function verifier(): JwtLibraryProofKeyVerifier
    {
        return new JwtLibraryProofKeyVerifier(Algorithms::all()->manager());
    }
}
