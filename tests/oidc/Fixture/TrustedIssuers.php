<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use DateInterval;
use DateTimeImmutable;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Oidc\Application\Key\PublishedKeySetProvider;
use Beffroi\Oidc\Application\Trust\IssuerAssertionValidator;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientJwksCache;
use Beffroi\Oidc\Bridge\InMemory\InMemoryIssuerAssertionReplayGuard;
use Beffroi\Oidc\Bridge\JwtLibrary\JwtLibraryCompactJwtReader;
use Beffroi\Oidc\Bridge\JwtLibrary\JwtLibraryJwtKeyVerifier;
use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Trust\TrustedIssuer;
use Beffroi\Oidc\Port\ClientJwksFetcherInterface;
use Beffroi\Oidc\Port\IssuerAssertionReplayGuardInterface;
use Beffroi\Oidc\Port\TrustedIssuersInterface;
use Psr\Clock\ClockInterface;
use Symfony\Component\Clock\MockClock;

/**
 * The third parties the tests trust the signature of (RFC 7523 §3): one issuer, signing with the key of the
 * suite, trusted for one client, for one source of identities and for the scopes the fixtures name.
 */
final readonly class TrustedIssuers
{
    public const string ISSUER = 'https://workforce.example.com';

    /**
     * What the subjects of its assertions are linked identities of (decision 0002).
     */
    public const string PROVIDER = 'workforce';

    /**
     * Where the issuer publishes its keys when a test has it publish them behind a URL rather than write them
     * down (RFC 7517 §5).
     */
    public const string JWKS_URI = 'https://workforce.example.com/jwks';

    /**
     * @param list<string>|null $clients the clients that may present its assertions, the job runner unless the test says otherwise
     * @param list<non-empty-string>|null $signingAlgorithms what it signs with, ES256 unless the test says otherwise
     * @param list<string>|null $trustedScopes what it is trusted for, the two the fixtures name unless the test says otherwise
     * @param ClientJwks|ClientUri|null $keys where its keys are, written down unless the test says otherwise
     */
    public static function workforce(
        ?array $clients = null,
        ?array $signingAlgorithms = null,
        ?array $trustedScopes = null,
        string $issuer = self::ISSUER,
        string $provider = self::PROVIDER,
        ClientJwks|ClientUri|null $keys = null,
    ): TrustedIssuer {
        return new TrustedIssuer(
            $issuer,
            $keys ?? ClientAssertions::publishedKeys(),
            $signingAlgorithms ?? ['ES256'],
            $clients ?? ['job-runner'],
            $provider,
            new Scopes(array_map(
                static fn (string $scope): Scope => new Scope($scope),
                $trustedScopes ?? ['invoices.read', 'invoices.write'],
            )),
        );
    }

    /**
     * What reads an assertion presented as an authorization, wired as the bundle wires it (RFC 7523 §3): the
     * reader and the verifier every JWT a third party signs goes through, the keys of the issuers read by the
     * one class that reads a published set and kept in a pool of their own, and a replay guard of their own.
     *
     * @param ClientJwksFetcherInterface|null $fetcher what reads a "jwks_uri" of an issuer, one answering the
     *                                                 key of the suite unless the test drives its own
     */
    public static function validator(
        TrustedIssuersInterface $issuers,
        ?IssuerAssertionReplayGuardInterface $replays = null,
        ?ClientJwksFetcherInterface $fetcher = null,
        ?ClockInterface $clock = null,
        ?DateInterval $cooldown = null,
    ): IssuerAssertionValidator {
        return new IssuerAssertionValidator(
            new JwtLibraryCompactJwtReader(),
            new JwtLibraryJwtKeyVerifier(Algorithms::all()->manager()),
            new PublishedKeySetProvider(
                $fetcher ?? new FakeClientJwksFetcher([ClientAssertions::publishedKeys()]),
                new InMemoryClientJwksCache(),
                $clock ?? new MockClock('2026-09-15T12:00:00+00:00'),
                $cooldown ?? new DateInterval('PT300S'),
            ),
            $issuers,
            $replays ?? new InMemoryIssuerAssertionReplayGuard(),
            new DateInterval('PT300S'),
            new DateInterval('PT30S'),
        );
    }

    /**
     * RFC 7523 §3: the claims an assertion of a trusted issuer carries, all of them, signed with the key of
     * the suite.
     *
     * @param array<string, mixed> $overrides
     *
     * @return array<string, mixed>
     */
    public static function claims(string $subject, string $audience, DateTimeImmutable $now, array $overrides = []): array
    {
        return [
            'iss' => self::ISSUER,
            'sub' => $subject,
            'aud' => $audience,
            'exp' => $now->getTimestamp() + 60,
            'iat' => $now->getTimestamp(),
            'jti' => 'assertion-' . $now->getTimestamp(),
            ...$overrides,
        ];
    }

    /**
     * @param array<string, mixed> $overrides
     * @param array<string, mixed> $header
     */
    public static function assertion(string $subject, string $audience, DateTimeImmutable $now, array $overrides = [], array $header = []): string
    {
        return ClientAssertions::signedWithKey(self::claims($subject, $audience, $now, $overrides), $header);
    }
}
