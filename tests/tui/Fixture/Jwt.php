<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Fixture;

use Beffroi\Tui\Json\Document;
use function explode;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use function sodium_base642bin;
use const SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING;

/**
 * A compact JWS as a test reads what this program signed: its header, its claims, and whether a key verifies it.
 */
final readonly class Jwt
{
    public static function header(string $jwt): Document
    {
        return Document::decode(self::part($jwt, 0), 'header');
    }

    public static function claims(string $jwt): Document
    {
        return Document::decode(self::part($jwt, 1), 'claims');
    }

    /**
     * @param array<array-key, mixed> $publicKey
     */
    public static function verifies(string $jwt, array $publicKey): bool
    {
        return new JWSVerifier(new AlgorithmManager([new ES256()]))->verifyWithKey(new CompactSerializer()->unserialize($jwt), new JWK($publicKey), 0);
    }

    private static function part(string $jwt, int $index): string
    {
        return sodium_base642bin(explode('.', $jwt)[$index] ?? '', SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }
}
