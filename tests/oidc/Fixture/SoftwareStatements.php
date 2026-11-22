<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use function bin2hex;
use DateTimeImmutable;
use function random_bytes;
use Beffroi\Oidc\Domain\Client\Registration\StatementIssuer;
use Jose\Component\Core\JWK;

/**
 * RFC 7591 §2.3
 */
final readonly class SoftwareStatements
{
    public const string ISSUER = 'https://store.example.com';

    public const string SOFTWARE_ID = 'invoice-reader';

    /**
     * @param list<non-empty-string>|null $signingAlgorithms
     */
    public static function authority(?array $signingAlgorithms = null, string $issuer = self::ISSUER): StatementIssuer
    {
        return new StatementIssuer($issuer, ClientAssertions::publishedKeys(), $signingAlgorithms ?? ['ES256']);
    }

    /**
     * RFC 7591 §2
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
