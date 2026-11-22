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
 * RFC 7523 §3
 */
final class ClientAssertions
{
    public const string KEY_ID = 'client-key';

    /**
     * @var array<non-empty-string, JWK> by algorithm
     */
    private static array $privateKeys = [];

    public static function privateKey(?JoseSignatureAlgorithmInterface $algorithm = null): JWK
    {
        $algorithm ??= Algorithms::es256();

        return self::$privateKeys[$algorithm->name()] ??= new JWK([
            ...$algorithm->generateKey()->all(),
            'kid' => self::KEY_ID,
        ]);
    }

    public static function publishedKeys(?JoseSignatureAlgorithmInterface $algorithm = null): ClientJwks
    {
        /** @var list<array<string, mixed>> $keys */
        $keys = [self::privateKey($algorithm)->toPublic()->all()];

        return new ClientJwks($keys);
    }

    /**
     * RFC 7523 §3
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
     * RFC 7523 §2.2
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
