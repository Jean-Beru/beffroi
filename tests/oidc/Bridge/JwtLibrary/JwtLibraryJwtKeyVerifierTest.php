<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Bridge\JwtLibrary;

use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Oidc\Bridge\JwtLibrary\JwtLibraryCompactJwtReader;
use Beffroi\Oidc\Bridge\JwtLibrary\JwtLibraryJwtKeyVerifier;
use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use Beffroi\Oidc\Exception\InvalidJwtException;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Core §10.1, RFC 8725 §3.10
 */
final class JwtLibraryJwtKeyVerifierTest extends TestCase
{
    /**
     * OIDC Core §10.1
     */
    #[Test]
    public function aTokenThatNamesNoKeyIsVerifiedUnderTheOneKeyThatCouldHaveSignedIt(): void
    {
        // Given
        $signing = Algorithms::es256()->generateKey();
        $keys = new ClientJwks([self::published($signing), self::published(Algorithms::rs256()->generateKey())]);

        // When
        self::verifier()->verify(self::signed($signing), $keys, ['ES256', 'RS256']);

        // Then
        $this->expectNotToPerformAssertions();
    }

    /**
     * OIDC Core §10.1
     */
    #[Test]
    public function aTokenThatNamesNoKeyIsRefusedWhenSeveralKeysCouldHaveSignedIt(): void
    {
        // Given
        $signing = Algorithms::es256()->generateKey();
        $keys = new ClientJwks([self::published(Algorithms::es256()->generateKey()), self::published($signing)]);

        // Then
        $this->expectException(InvalidJwtException::class);
        $this->expectExceptionMessageIs('The token names no "kid", and the client publishes several keys that could have signed it (OIDC Core section 10.1).');

        // When
        self::verifier()->verify(self::signed($signing), $keys, ['ES256']);
    }

    /**
     * RFC 7515 §4.1.4
     */
    #[Test]
    public function aTokenThatNamesItsKeyIsVerifiedUnderThatKeyAmongSeveral(): void
    {
        // Given
        $signing = new JWK([...Algorithms::es256()->generateKey()->all(), 'kid' => 'two']);
        $keys = new ClientJwks([
            self::published(new JWK([...Algorithms::es256()->generateKey()->all(), 'kid' => 'one'])),
            self::published($signing),
        ]);

        // When
        self::verifier()->verify(self::signed($signing, 'two'), $keys, ['ES256']);

        // Then
        $this->expectNotToPerformAssertions();
    }

    private static function signed(JWK $key, ?string $keyId = null): UnverifiedJwt
    {
        $jws = new JWSBuilder(new AlgorithmManager([Algorithms::es256()->joseAlgorithm()]))
            ->create()
            ->withPayload(json_encode([
                'iss' => 'client',
            ], JSON_THROW_ON_ERROR))
            ->addSignature($key, [
                'alg' => 'ES256',
                ...(
                    $keyId === null
                        ? []
                        : [
                            'kid' => $keyId,
                        ]
                ),
            ])
            ->build();

        return new JwtLibraryCompactJwtReader()->read(new CompactSerializer()->serialize($jws, 0));
    }

    /**
     * @return array<string, mixed>
     */
    private static function published(JWK $key): array
    {
        /** @var array<string, mixed> $members */
        $members = $key->toPublic()->all();

        return $members;
    }

    private static function verifier(): JwtLibraryJwtKeyVerifier
    {
        return new JwtLibraryJwtKeyVerifier(Algorithms::all()->manager());
    }
}
