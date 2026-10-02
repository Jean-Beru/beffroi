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
use Beffroi\Oidc\Domain\Token\Base64Url;
use Beffroi\Oidc\Domain\Token\KeyConfirmation;
use Beffroi\Oidc\Port\DpopNonceInterface;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use function json_encode;
use const JSON_THROW_ON_ERROR;

/**
 * The client side of DPoP (RFC 9449 §4.2): a key pair of its own, the claims of a proof and the compact
 * JWS a client would put in the header. Two keys, so that a proof of one can be presented against a
 * token bound to the other. Never leaves the test suite.
 */
final class Proofs
{
    private static ?JWK $key = null;

    private static ?JWK $otherKey = null;

    /**
     * The key the client proves possession of, ES256, as a client would generate it.
     */
    public static function key(): JWK
    {
        return self::$key ??= Algorithms::es256()->generateKey();
    }

    /**
     * Another key, of another client or of whoever stole a token.
     */
    public static function otherKey(): JWK
    {
        return self::$otherKey ??= Algorithms::es256()->generateKey();
    }

    public static function thumbprintOf(JWK $key): KeyConfirmation
    {
        return new KeyConfirmation($key->toPublic()->thumbprint('sha256'));
    }

    /**
     * A proof for one request, as RFC 9449 §4.2 has it: the public key in the header, the method and the
     * URL of the request in the claims, and the access token it accompanies when there is one.
     *
     * @param array<string, mixed> $overrides claims written over the ones of the specification, a null
     *                                        value leaving the claim out
     * @param array<string, mixed> $header what is written over the header
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
     * RFC 9449 §4.2 "ath": the base64url of the SHA-256 of the access token the proof accompanies.
     */
    public static function accessTokenHash(string $accessToken): string
    {
        return Base64Url::encode(hash('sha256', $accessToken, true));
    }

    /**
     * The verifier as the bundle wires it: the reader of every JWT a client signs, the algorithms of the
     * provider, the proofs already seen in the memory of the test, and no nonce unless the test wires one.
     */
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
