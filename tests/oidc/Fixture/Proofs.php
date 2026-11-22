<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use DateInterval;
use DateTimeImmutable;
use function hash;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Oidc\Application\Dpop\DpopProofValidator;
use Beffroi\Oidc\Application\Dpop\DpopProofVerifier;
use Beffroi\Oidc\Bridge\InMemory\InMemoryDpopProofReplayGuard;
use Beffroi\Oidc\Bridge\JwtLibrary\JwtLibraryCompactJwtReader;
use Beffroi\Oidc\Bridge\JwtLibrary\JwtLibraryProofKeyVerifier;
use Beffroi\Oidc\Bridge\Null\NoDpopNonce;
use Beffroi\Oidc\Domain\Dpop\DpopProof;
use Beffroi\Core\Domain\Encoding\Base64Url;
use Beffroi\Oidc\Domain\Token\KeyConfirmation;
use Beffroi\Oidc\Port\DpopNonceInterface;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use function json_encode;
use const JSON_THROW_ON_ERROR;

/**
 * RFC 9449 §4.2
 */
final class Proofs
{
    private static ?JWK $key = null;

    private static ?JWK $otherKey = null;

    public static function key(): JWK
    {
        return self::$key ??= Algorithms::es256()->generateKey();
    }

    public static function otherKey(): JWK
    {
        return self::$otherKey ??= Algorithms::es256()->generateKey();
    }

    public static function thumbprintOf(JWK $key): KeyConfirmation
    {
        return new KeyConfirmation($key->toPublic()->thumbprint('sha256'));
    }

    /**
     * RFC 9449 §4.2
     *
     * @param array<string, mixed> $overrides a null value leaves the claim out
     * @param array<string, mixed> $header
     */
    public static function proof(
        string $method,
        string $url,
        DateTimeImmutable $now,
        ?string $accessToken = null,
        array $overrides = [],
        array $header = [],
        ?JWK $key = null,
    ): string {
        $key ??= self::key();
        $claims = [
            'jti' => 'proof-' . $now->getTimestamp(),
            'htm' => $method,
            'htu' => $url,
            'iat' => $now->getTimestamp(),
            ...(
                $accessToken === null
                    ? []
                    : [
                        'ath' => self::accessTokenHash($accessToken),
                    ]
            ),
            ...$overrides,
        ];
        foreach ($claims as $name => $value) {
            if ($value === null) {
                unset($claims[$name]);
            }
        }
        $jws = new JWSBuilder(new AlgorithmManager([Algorithms::es256()->joseAlgorithm()]))
            ->create()
            ->withPayload(json_encode($claims, JSON_THROW_ON_ERROR))
            ->addSignature($key, [
                'alg' => 'ES256',
                'typ' => DpopProof::TYPE,
                DpopProof::KEY => $key->toPublic()->all(),
                ...$header,
            ])
            ->build();

        return new CompactSerializer()->serialize($jws, 0);
    }

    /**
     * RFC 9449 §4.2
     */
    public static function accessTokenHash(string $accessToken): string
    {
        return Base64Url::encode(hash('sha256', $accessToken, true));
    }

    public static function verifier(?DpopNonceInterface $nonces = null, int $maximumAge = 60, int $leeway = 5): DpopProofVerifier
    {
        return new DpopProofVerifier(
            new JwtLibraryCompactJwtReader(),
            new JwtLibraryProofKeyVerifier(Algorithms::all()->manager()),
            new DpopProofValidator(
                new InMemoryDpopProofReplayGuard(),
                $nonces ?? new NoDpopNonce(),
                new DateInterval('PT' . $maximumAge . 'S'),
                new DateInterval('PT' . $leeway . 'S'),
            ),
            Algorithms::all(),
        );
    }
}
