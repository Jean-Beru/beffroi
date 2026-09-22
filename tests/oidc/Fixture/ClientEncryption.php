<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Oidc\Domain\Client\ClientJwks;
use Heidi\Oidc\Domain\Client\ResponseEncryption;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use PHPUnit\Framework\Assert;

/**
 * The client side of what the provider encrypts for it: one P-256 key pair the client publishes for
 * encryption, and the opening a client performs on a document addressed to it. Never leaves the test
 * suite.
 */
final class ClientEncryption
{
    public const string KEY_ID = 'client-encryption-key';

    private static ?JWK $privateKey = null;

    /**
     * The private half, which only the client holds.
     */
    public static function privateKey(): JWK
    {
        return self::$privateKey ??= new JWK([
            ...Algorithms::ecdhEsA256Kw()->generateKey()->all(),
            'kid' => self::KEY_ID,
        ]);
    }

    /**
     * What the client publishes: the key it signs its assertions with, and the one it is encrypted to.
     */
    public static function publishedKeys(): ClientJwks
    {
        /** @var list<array<string, mixed>> $keys */
        $keys = [
            ClientAssertions::privateKey()->toPublic()->all(),
            self::privateKey()->toPublic()->all(),
        ];

        return new ClientJwks($keys);
    }

    public static function registration(): ResponseEncryption
    {
        return new ResponseEncryption(Algorithms::ecdhEsA256Kw(), Algorithms::a256Gcm());
    }

    /**
     * The document as the client reads it: the JWE opened with the private half, and its payload, which
     * is a compact JWS when the provider signed before encrypting.
     *
     * @return array{header: array<string, mixed>, payload: string}
     */
    public static function open(string $compactJwe): array
    {
        $jwe = new CompactSerializer()->unserialize($compactJwe);
        $opened = new JWEDecrypter(Algorithms::encryption()->manager())->decryptUsingKey($jwe, self::privateKey(), 0);
        Assert::assertTrue($opened, 'The client could not open the document addressed to it.');
        $payload = $jwe->getPayload();
        Assert::assertIsString($payload);

        return [
            'header' => $jwe->getSharedProtectedHeader(),
            'payload' => $payload,
        ];
    }
}
