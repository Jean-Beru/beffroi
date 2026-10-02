<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use function bin2hex;
use DateTimeImmutable;
use function random_bytes;
use Beffroi\Oidc\Domain\Client\Registration\StatementIssuer;
use Jose\Component\Core\JWK;

/**
 * The authority the tests pin the software statements of (RFC 7591 §2.3): one, signing ES256 with the key
 * of the suite, and the statements it signs.
 */
final readonly class SoftwareStatements
{
    public const string ISSUER = 'https://store.example.com';

    /**
     * What the product the statement describes calls itself, the same across every installation of it.
     */
    public const string SOFTWARE_ID = 'invoice-reader';

    /**
     * @param list<non-empty-string>|null $signingAlgorithms what it signs with, ES256 unless the test says otherwise
     */
    public static function authority(?array $signingAlgorithms = null, string $issuer = self::ISSUER): StatementIssuer
    {
        return new StatementIssuer($issuer, ClientAssertions::publishedKeys(), $signingAlgorithms ?? ['ES256']);
    }

    /**
     * The claims of a statement: what it says about itself, and what it says about the client, which is
     * client metadata under the names of RFC 7591 §2.
     *
     * Each one carries an identifier of its own, because one statement registers one client and the store
     * that remembers them outlives a test: two statements minted in the same second are two statements.
     *
     * @param array<string, mixed> $overrides
     *
     * @return array<string, mixed>
     */
    public static function claims(string $audience, DateTimeImmutable $now, array $overrides = []): array
    {
        return [
            'iss' => self::ISSUER,
            'aud' => $audience,
            'exp' => $now->getTimestamp() + 60,
            'iat' => $now->getTimestamp(),
            'jti' => 'statement-' . bin2hex(random_bytes(8)),
            'software_id' => self::SOFTWARE_ID,
            'software_version' => '2.1.0',
            'client_name' => 'Invoice reader, attested',
            ...$overrides,
        ];
    }

    /**
     * @param array<string, mixed> $overrides
     * @param array<string, mixed> $header
     */
    public static function statement(
        string $audience,
        DateTimeImmutable $now,
        array $overrides = [],
        array $header = [],
        ?JWK $key = null,
    ): string {
        return ClientAssertions::signedWithKey(self::claims($audience, $now, $overrides), $header, $key);
    }
}
