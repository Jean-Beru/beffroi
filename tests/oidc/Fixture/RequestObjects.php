<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use function base64_encode;
use DateInterval;
use DateTimeImmutable;
use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Bridge\JwtLibrary\JoseSignatureAlgorithmInterface;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryJweDecrypter;
use Beffroi\Core\Bridge\Key\SealedKeyProvider;
use Beffroi\Core\Port\JweDecrypterInterface;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Keys;
use Beffroi\Oidc\Application\Authorization\RequestObjectReader;
use Beffroi\Oidc\Application\Authorization\RequestObjectResolver;
use Beffroi\Oidc\Application\Authorization\RequestObjectValidator;
use Beffroi\Oidc\Application\Client\ClientKeySetProvider;
use Beffroi\Oidc\Bridge\JwtLibrary\JwtLibraryCompactJwtReader;
use Beffroi\Oidc\Bridge\JwtLibrary\JwtLibraryJwtKeyVerifier;
use Beffroi\Oidc\Domain\Token\JwtPayload;
use Beffroi\Oidc\Port\ClientRepositoryInterface;
use Beffroi\Oidc\Port\RequestObjectFetcherInterface;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Psr\Clock\ClockInterface;
use function rtrim;
use function strtr;

/**
 * RFC 9101
 */
final class RequestObjects
{
    public const string JTI = 'b2f1c0a9-8e7d-4c6b-9a5f-0d1e2f3a4b5c';

    /**
     * RFC 9101 §4, CIBA Core §7.1.1
     *
     * @param array<string, mixed> $parameters
     *
     * @return array<string, mixed>
     */
    public static function claims(string $clientId, string $issuer, DateTimeImmutable $now, array $parameters = []): array
    {
        return [
            'iss' => $clientId,
            'aud' => $issuer,
            'iat' => $now->getTimestamp(),
            'jti' => self::JTI,
            'nbf' => $now->getTimestamp(),
            'exp' => $now->getTimestamp() + 300,
            'client_id' => $clientId,
            ...$parameters,
        ];
    }

    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $header
     */
    public static function signed(
        array $claims,
        array $header = [],
        ?JWK $key = null,
        ?JoseSignatureAlgorithmInterface $algorithm = null,
    ): string {
        return ClientAssertions::signedWithKey($claims, $header, $key, $algorithm);
    }

    /**
     * RFC 7515 §4.1.1, RFC 7518 §3.6
     *
     * @param array<string, mixed> $claims
     */
    public static function unsigned(array $claims): string
    {
        return (
            self::segment(JwtPayload::encode([
                'alg' => 'none',
            ]))
            . '.'
            . self::segment(JwtPayload::encode($claims))
            . '.'
        );
    }

    /**
     * RFC 9101 §6.1
     *
     * @param array<string, mixed> $publicJwk
     * @param array<string, mixed> $header
     */
    public static function encryptedTo(array $publicJwk, string $payload, array $header = []): string
    {
        $jwe = new JWEBuilder(Algorithms::encryption()->manager())
            ->create()
            ->withPayload($payload)
            ->withSharedProtectedHeader([
                'alg' => $publicJwk['alg'] ?? null,
                'enc' => Algorithms::a256Gcm()->name(),
                'kid' => $publicJwk['kid'] ?? null,
                ...$header,
            ])
            ->addRecipient(new JWK($publicJwk))
            ->build();

        return new CompactSerializer()->serialize($jwe, 0);
    }

    public static function resolver(
        ClientRepositoryInterface $clients,
        ClockInterface $clock,
        ?RequestObjectFetcherInterface $references = null,
        ?ClientKeySetProvider $keys = null,
        ?JweDecrypterInterface $decrypter = null,
    ): RequestObjectResolver {
        return new RequestObjectResolver(
            $clients,
            new RequestObjectReader(new JwtLibraryCompactJwtReader(), $decrypter ?? self::decrypter()),
            new JwtLibraryJwtKeyVerifier(Algorithms::all()->manager()),
            $keys ?? Methods::keySetProvider(clock: $clock),
            new RequestObjectValidator(new DateInterval('PT3600S'), new DateInterval('PT30S')),
            $references ?? new FakeRequestObjectFetcher(),
            Algorithms::all(),
            $clock,
        );
    }

    private static function decrypter(): JweDecrypterInterface
    {
        return new JwtLibraryJweDecrypter(new SealedKeyProvider(new InMemoryTenantKeyRepository(), Keys::opened()), Algorithms::encryption());
    }

    private static function segment(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
