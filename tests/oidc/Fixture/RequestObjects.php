<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use function base64_encode;
use DateInterval;
use DateTimeImmutable;
use Heidi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Heidi\Core\Bridge\JwtLibrary\JoseSignatureAlgorithmInterface;
use Heidi\Core\Bridge\JwtLibrary\JwtLibraryJweDecrypter;
use Heidi\Core\Bridge\Key\SealedKeyProvider;
use Heidi\Core\Port\JweDecrypterInterface;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\Keys;
use Heidi\Oidc\Application\Authorization\RequestObjectReader;
use Heidi\Oidc\Application\Authorization\RequestObjectResolver;
use Heidi\Oidc\Application\Authorization\RequestObjectValidator;
use Heidi\Oidc\Application\Client\ClientKeySetProvider;
use Heidi\Oidc\Bridge\JwtLibrary\JwtLibraryCompactJwtReader;
use Heidi\Oidc\Bridge\JwtLibrary\JwtLibraryJwtKeyVerifier;
use Heidi\Oidc\Domain\Token\JwtPayload;
use Heidi\Oidc\Port\ClientRepositoryInterface;
use Heidi\Oidc\Port\RequestObjectFetcherInterface;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Psr\Clock\ClockInterface;
use function rtrim;
use function strtr;

/**
 * The client side of RFC 9101: the claims a request object carries, the compact JWS a client would send,
 * and the unsigned object of a client that registered "none". The key is the one the client assertions
 * of the suite publish, a client having one set of keys whatever it signs. Never leaves the test suite.
 */
final class RequestObjects
{
    /**
     * The "jti" of an object nobody replays: one value, so that two objects built alike are the same
     * object, which is what a test of a replay sends twice and what every other test sends once.
     */
    public const string JTI = 'b2f1c0a9-8e7d-4c6b-9a5f-0d1e2f3a4b5c';

    /**
     * RFC 9101 §4: the request is the claims, "iss" naming the client and "aud" the provider. CIBA Core
     * §7.1.1 adds "iat" and "jti" to the ones a backchannel authentication request carries, and a client
     * that writes them writes them everywhere.
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
     * @param JoseSignatureAlgorithmInterface|null $algorithm what the client registered in
     *                                                        "request_object_signing_alg", null for the
     *                                                        ES256 every client of the tests signs with
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
     * RFC 7515 §4.1.1, RFC 7518 §3.6: the two segments and the empty signature of a JWS with "alg":
     * "none", which is what an unsigned request object is.
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
     * RFC 9101 §6.1: what a client encrypts to a key the provider publishes, the "alg" being the one the
     * key is published for and the "enc" the one the provider is wired with. The payload is a compact
     * JWS for every client but the one that registered "none", whose claims travel as they are.
     *
     * @param array<string, mixed> $publicJwk the key of the tenant, as its JWK Set publishes it
     * @param array<string, mixed> $header what the JWE announces beside the algorithms, "cty" for a
     *                                     nested token (RFC 7519 §5.2)
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

    /**
     * A tenant that publishes no encryption key at all: what a deployment nobody encrypts to opens, which
     * is nothing.
     */
    private static function decrypter(): JweDecrypterInterface
    {
        return new JwtLibraryJweDecrypter(new SealedKeyProvider(new InMemoryTenantKeyRepository(), Keys::sealer()), Algorithms::encryption());
    }

    private static function segment(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
