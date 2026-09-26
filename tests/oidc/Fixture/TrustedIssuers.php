<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use DateTimeImmutable;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Trust\TrustedIssuer;

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
     * @param list<string>|null $clients the clients that may present its assertions, the job runner unless the test says otherwise
     * @param list<non-empty-string>|null $signingAlgorithms what it signs with, ES256 unless the test says otherwise
     * @param list<string>|null $trustedScopes what it is trusted for, the two the fixtures name unless the test says otherwise
     */
    public static function workforce(
        ?array $clients = null,
        ?array $signingAlgorithms = null,
        ?array $trustedScopes = null,
        string $issuer = self::ISSUER,
        string $provider = self::PROVIDER,
    ): TrustedIssuer {
        return new TrustedIssuer(
            $issuer,
            ClientAssertions::publishedKeys(),
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
