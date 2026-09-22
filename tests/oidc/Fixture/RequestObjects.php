<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use function base64_encode;
use DateInterval;
use DateTimeImmutable;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Oidc\Application\Authorization\RequestObjectResolver;
use Heidi\Oidc\Application\Authorization\RequestObjectValidator;
use Heidi\Oidc\Application\Client\ClientKeySetProvider;
use Heidi\Oidc\Bridge\JwtLibrary\JwtLibraryCompactJwtReader;
use Heidi\Oidc\Bridge\JwtLibrary\JwtLibraryJwtKeyVerifier;
use Heidi\Oidc\Domain\Token\JwtPayload;
use Heidi\Oidc\Port\ClientRepositoryInterface;
use Heidi\Oidc\Port\RequestObjectFetcherInterface;
use Jose\Component\Core\JWK;
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
     * RFC 9101 §4: the request is the claims, "iss" naming the client and "aud" the provider.
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
    public static function signed(array $claims, array $header = [], ?JWK $key = null): string
    {
        return ClientAssertions::signedWithKey($claims, $header, $key);
    }

    /**
     * RFC 7515 §4.1.1, RFC 7518 §3.6: the two segments and the empty signature of a JWS with "alg":
     * "none", which is what an unsigned request object is.
     *
     * @param array<string, mixed> $claims
     */
    public static function unsigned(array $claims): string
    {
        return self::segment(JwtPayload::encode([
            'alg' => 'none',
        ])) . '.' . self::segment(JwtPayload::encode($claims)) . '.';
    }

    public static function resolver(ClientRepositoryInterface $clients, ClockInterface $clock, ?RequestObjectFetcherInterface $references = null, ?ClientKeySetProvider $keys = null): RequestObjectResolver
    {
        return new RequestObjectResolver(
            $clients,
            new JwtLibraryCompactJwtReader(),
            new JwtLibraryJwtKeyVerifier(Algorithms::all()->manager()),
            $keys ?? Methods::keySetProvider(clock: $clock),
            new RequestObjectValidator(new DateInterval('PT3600S'), new DateInterval('PT30S')),
            $references ?? new FakeRequestObjectFetcher(),
            Algorithms::all(),
            $clock,
        );
    }

    private static function segment(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
