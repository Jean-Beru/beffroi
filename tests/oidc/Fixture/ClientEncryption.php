<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Domain\Client\ResponseEncryption;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use PHPUnit\Framework\Assert;

final class ClientEncryption
{
    public const string KEY_ID = 'client-encryption-key';

    private static ?JWK $privateKey = null;

    public static function privateKey(): JWK
    {
        return self::$privateKey ??= new JWK([
            ...Algorithms::ecdhEsA256Kw()->generateKey()->all(),
            'kid' => self::KEY_ID,
        ]);
    }

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
