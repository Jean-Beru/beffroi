<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Key;

use function base64_encode;
use function getenv;
use App\Tests\Symfony\Functional\Doctrine\DatabaseTestCase;
use Beffroi\Core\Application\Key\KeyTakeOver;
use Beffroi\Core\Port\TenantKeyRepositoryInterface;
use Beffroi\Core\Tests\Fixture\Algorithms;
use function is_string;
use function random_bytes;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use function str_starts_with;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\KeyManagement\Dsn;
use Symfony\Component\KeyManagement\Envelope;
use Symfony\Contracts\HttpClient\HttpClientInterface;

final class VaultTransitCustodyTest extends DatabaseTestCase
{
    private const string SCHEME = 'hashicorp-vault-transit://';

    private const string TRANSIT_KEY = 'beffroi-default';

    private HttpClientInterface $vault;

    protected function setUp(): void
    {
        $dsn = getenv('BEFFROI_TEST_KMS_DSN');
        if (! is_string($dsn) || ! str_starts_with($dsn, self::SCHEME)) {
            static::markTestSkipped('The kernel seals with sodium; set BEFFROI_TEST_KMS_DSN to a Vault DSN to run this test.');
        }
        parent::setUp();
        $this->vault = self::vaultClient(Dsn::fromString($dsn));
    }

    #[Test]
    public function theDataKeyOfASealedKeyIsWrappedByTheTransitKeyOfTheTenant(): void
    {
        // Given
        $takeOver = self::service('test.beffroi.key_take_over', KeyTakeOver::class);

        // When
        $rotated = $takeOver->rotate(self::tenant(), Algorithms::rs256(), self::context());

        // Then
        $stored = self::service('test.beffroi.keys', TenantKeyRepositoryInterface::class)
            ->find(self::tenant(), $rotated->kid) ?? static::fail('The key is stored.');
        $envelope = Envelope::fromBytes($stored->sealedPrivateJwk);
        static::assertSame(self::TRANSIT_KEY, $envelope->keyId);
        static::assertIsString($envelope->wrappedDek);
        static::assertStringStartsWith('vault:v', $envelope->wrappedDek);
    }

    #[Test]
    public function theTransitKeyOfTheTenantKeepsItsMaterialToItself(): void
    {
        // When
        $response = $this->vault->request('GET', 'transit/keys/' . self::TRANSIT_KEY);

        // Then
        static::assertSame(200, $response->getStatusCode());
        $key = $response->toArray()['data'] ?? [];
        static::assertIsArray($key);
        static::assertSame('aes256-gcm96', $key['type'] ?? null);
        static::assertTrue($key['derived'] ?? null);
        static::assertFalse($key['exportable'] ?? null);
        static::assertFalse($key['allow_plaintext_backup'] ?? null);
        static::assertFalse($key['deletion_allowed'] ?? null);
    }

    #[Test]
    public function theTokenOfTheOpMintsADataKeyUnderTheKeyOfTheTenant(): void
    {
        // When
        $response = $this->vault->request('POST', 'transit/datakey/plaintext/' . self::TRANSIT_KEY, [
            'json' => [
                'bits' => 256,
                'context' => base64_encode('beffroi:signing-key:v2:default'),
            ],
        ]);

        // Then
        static::assertSame(200, $response->getStatusCode());
        $data = $response->toArray()['data'] ?? [];
        static::assertIsArray($data);
        static::assertIsString($data['ciphertext'] ?? null);
        static::assertStringStartsWith('vault:v', $data['ciphertext']);
    }

    #[Test]
    public function theTokenOfTheOpWrapsADataKeyItHoldsUnderTheKeyOfTheTenant(): void
    {
        // When
        $response = $this->vault->request('POST', 'transit/encrypt/' . self::TRANSIT_KEY, [
            'json' => [
                'plaintext' => base64_encode(random_bytes(32)),
                'context' => base64_encode('beffroi:data-key:default.user'),
            ],
        ]);

        // Then
        static::assertSame(200, $response->getStatusCode());
        $data = $response->toArray()['data'] ?? [];
        static::assertIsArray($data);
        static::assertIsString($data['ciphertext'] ?? null);
        static::assertStringStartsWith('vault:v', $data['ciphertext']);
    }

    #[Test]
    #[DataProvider('provideRefusedRequests')]
    public function theTokenOfTheOpIsRefusedEverythingElse(string $method, string $path): void
    {
        // When
        $response = $this->vault->request($method, $path);

        // Then
        static::assertSame(403, $response->getStatusCode(), sprintf('%s %s is refused to the OP.', $method, $path));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideRefusedRequests(): iterable
    {
        yield 'exporting the key' => ['GET', 'transit/export/encryption-key/' . self::TRANSIT_KEY];
        yield 'backing the key up' => ['GET', 'transit/backup/' . self::TRANSIT_KEY];
        yield 'rotating the key' => ['POST', 'transit/keys/' . self::TRANSIT_KEY . '/rotate'];
        yield 'changing the configuration of the key' => ['POST', 'transit/keys/' . self::TRANSIT_KEY . '/config'];
        yield 'deleting the key' => ['DELETE', 'transit/keys/' . self::TRANSIT_KEY];
        yield 'creating a key of another tenant' => ['POST', 'transit/keys/beffroi-other'];
        yield 'listing the keys' => ['GET', 'transit/keys?list=true'];
        yield 'a data key outside the prefix' => ['POST', 'transit/datakey/plaintext/other'];
        yield 'decrypting outside the prefix' => ['POST', 'transit/decrypt/other'];
        yield 'encrypting outside the prefix' => ['POST', 'transit/encrypt/other'];
        yield 'reading a key outside the prefix' => ['GET', 'transit/keys/other'];
        yield 'the policies' => ['GET', 'sys/policies/acl/beffroi-op'];
    }

    private static function vaultClient(Dsn $dsn): HttpClientInterface
    {
        $scheme = $dsn->getOption('scheme', 'https');
        $path = $dsn->path === '' || $dsn->path === '/' ? '/v1/' : $dsn->path;

        return HttpClient::createForBaseUri(
            sprintf('%s://%s%s%s', is_string($scheme) ? $scheme : 'https', $dsn->host, $dsn->port === null ? '' : ':' . $dsn->port, $path),
            [
                'headers' => [
                    'X-Vault-Token' => (string) $dsn->user,
                ],
            ],
        );
    }
}
