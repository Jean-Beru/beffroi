<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use function base64_encode;
use DateTimeImmutable;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Oidc\Application\Client\ClientAuthenticationRequestParser;
use Heidi\Oidc\Domain\Client\ClientJwks;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use function rtrim;
use function strtr;

/**
 * The client side of "private_key_jwt" and of "client_secret_jwt": one ES256 key pair for the suite, the
 * claims RFC 7523 §3 asks for, and the compact JWS a client would send. Never leaves the test suite.
 */
final class ClientAssertions
{
    public const string KEY_ID = 'client-key';

    private static ?JWK $privateKey = null;

    /**
     * The private key of the client, ES256, with a "kid".
     */
    public static function privateKey(): JWK
    {
        return self::$privateKey ??= new JWK([
            ...Algorithms::es256()->generateKey()->all(),
            'kid' => self::KEY_ID,
        ]);
    }

    /**
     * What the client publishes, inline or behind its "jwks_uri".
     */
    public static function publishedKeys(): ClientJwks
    {
        /** @var list<array<string, mixed>> $keys */
        $keys = [self::privateKey()->toPublic()->all()];

        return new ClientJwks($keys);
    }

    /**
     * RFC 7523 §3: "iss" and "sub" name the client, "aud" names where it is sent, and "exp", "iat" and
     * "jti" are all there.
     *
     * @param array<string, mixed> $overrides
     *
     * @return array<string, mixed>
     */
    public static function claims(string $clientId, string $audience, DateTimeImmutable $now, array $overrides = []): array
    {
        return [
            'iss' => $clientId,
            'sub' => $clientId,
            'aud' => $audience,
            'exp' => $now->getTimestamp() + 60,
            'iat' => $now->getTimestamp(),
            'jti' => 'assertion-' . $now->getTimestamp(),
            ...$overrides,
        ];
    }

    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $header
     */
    public static function signedWithKey(array $claims, array $header = [], ?JWK $key = null): string
    {
        $key ??= self::privateKey();

        return self::sign(new AlgorithmManager([Algorithms::es256()->joseAlgorithm()]), $key, $claims, [
            'alg' => 'ES256',
            'kid' => self::KEY_ID,
            ...$header,
        ]);
    }

    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $header
     */
    public static function signedWithSecret(array $claims, string $secret, array $header = []): string
    {
        $key = new JWK([
            'kty' => 'oct',
            'k' => rtrim(strtr(base64_encode($secret), '+/', '-_'), '='),
        ]);

        return self::sign(new AlgorithmManager([new HS256()]), $key, $claims, [
            'alg' => 'HS256',
            ...$header,
        ]);
    }

    /**
     * The two parameters of RFC 7523 §2.2, as a request body carries them.
     *
     * @return array<string, string>
     */
    public static function parameters(string $assertion): array
    {
        return [
            'client_assertion_type' => ClientAuthenticationRequestParser::ASSERTION_TYPE,
            'client_assertion' => $assertion,
        ];
    }

    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $header
     */
    private static function sign(AlgorithmManager $algorithms, JWK $key, array $claims, array $header): string
    {
        $jws = new JWSBuilder($algorithms)
            ->create()
            ->withPayload(json_encode($claims, JSON_THROW_ON_ERROR))
            ->addSignature($key, $header)
            ->build();

        return new CompactSerializer()->serialize($jws, 0);
    }
}
