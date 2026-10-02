<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use function base64_encode;
use DateTimeImmutable;
use Beffroi\Core\Bridge\JwtLibrary\JoseSignatureAlgorithmInterface;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Oidc\Application\Client\ClientAuthenticationRequestParser;
use Beffroi\Oidc\Domain\Client\ClientJwks;
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
 * The client side of "private_key_jwt" and of "client_secret_jwt": one key pair per algorithm asked for,
 * the claims RFC 7523 §3 asks for, and the compact JWS a client would send. ES256 is what a caller that
 * names no algorithm gets; RS256 is what the Dynamic OP plan signs with, so a test that reproduces a module
 * names it. Never leaves the test suite.
 */
final class ClientAssertions
{
    public const string KEY_ID = 'client-key';

    /**
     * One pair per algorithm, drawn once: generating an RSA key is slow enough to be worth keeping.
     *
     * @var array<non-empty-string, JWK>
     */
    private static array $privateKeys = [];

    /**
     * The private key of the client, with a "kid".
     */
    public static function privateKey(?JoseSignatureAlgorithmInterface $algorithm = null): JWK
    {
        $algorithm ??= Algorithms::es256();

        return self::$privateKeys[$algorithm->name()] ??= new JWK([
            ...$algorithm->generateKey()->all(),
            'kid' => self::KEY_ID,
        ]);
    }

    /**
     * What the client publishes, inline or behind its "jwks_uri".
     */
    public static function publishedKeys(?JoseSignatureAlgorithmInterface $algorithm = null): ClientJwks
    {
        /** @var list<array<string, mixed>> $keys */
        $keys = [self::privateKey($algorithm)->toPublic()->all()];

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
     * @param JWK|null $key the key to sign with, null for the pair this algorithm publishes
     */
    public static function signedWithKey(
        array $claims,
        array $header = [],
        ?JWK $key = null,
        ?JoseSignatureAlgorithmInterface $algorithm = null,
    ): string {
        $algorithm ??= Algorithms::es256();

        return self::sign(new AlgorithmManager([$algorithm->joseAlgorithm()]), $key ?? self::privateKey($algorithm), $claims, [
            'alg' => $algorithm->name(),
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
