<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Key;

use AsyncAws\Core\Configuration;
use AsyncAws\Kms\Input\DecryptRequest;
use AsyncAws\Kms\KmsClient;
use function getenv;
use App\Tests\Symfony\Functional\Doctrine\DatabaseTestCase;
use Beffroi\Core\Application\Key\KeyTakeOver;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Port\KeySealerInterface;
use Beffroi\Core\Port\TenantKeyRepositoryInterface;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use function is_string;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use function str_starts_with;
use function strlen;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\KeyManagement\Dsn;
use Symfony\Component\KeyManagement\Envelope;
use Symfony\Component\KeyManagement\Exception\DecryptionFailedException;

final class AwsKmsCustodyTest extends DatabaseTestCase
{
    private const string SCHEME = 'aws-kms://';

    private const string ALIAS = 'alias/beffroi-default';

    private Dsn $dsn;

    protected function setUp(): void
    {
        $dsn = getenv('BEFFROI_TEST_KMS_DSN');
        if (! is_string($dsn) || ! str_starts_with($dsn, self::SCHEME)) {
            static::markTestSkipped('The kernel seals with sodium; set BEFFROI_TEST_KMS_DSN to an AWS KMS DSN to run this test.');
        }
        parent::setUp();
        $this->dsn = Dsn::fromString($dsn);
    }

    #[Test]
    public function theEnvelopeOfASealedKeyNamesTheArnOfTheKeyBehindTheAliasOfTheTenant(): void
    {
        // Given
        $takeOver = self::service('test.beffroi.key_take_over', KeyTakeOver::class);
        $keyBehindTheAlias = $this->describeKey(self::ALIAS)['Arn'] ?? null;

        // When
        $rotated = $takeOver->rotate(self::tenant(), Algorithms::rs256(), self::context());

        // Then
        static::assertSame($keyBehindTheAlias, Envelope::fromBytes(self::sealedPrivateJwkOf($rotated))->keyId);
    }

    #[Test]
    public function theKmsUnwrapsTheDataKeyOfASealedKeyUnderNoContext(): void
    {
        // Given
        $envelope = Envelope::fromBytes(self::aSealedKey());

        // When
        $unwrapped = $this->kms()->decrypt(new DecryptRequest([
            'KeyId' => $envelope->keyId,
            'CiphertextBlob' => (string) $envelope->wrappedDek,
        ]));

        // Then
        static::assertSame(32, strlen((string) $unwrapped->getPlaintext()));
    }

    #[Test]
    public function aSealedKeyOpenedForAnotherTenantIsRefusedByTheLocalAead(): void
    {
        // Given
        $sealed = self::aSealedKey();

        // When
        try {
            self::service('test.beffroi.key_sealer', KeySealerInterface::class)->unseal(Fixtures::tenant('other'), $sealed);
            static::fail('The key of one tenant should not have been opened for another.');
        } catch (RuntimeException $exception) {
            // Then
            static::assertSame('The sealed key could not be opened.', $exception->getMessage());
            $refusal = $exception->getPrevious();
            static::assertInstanceOf(DecryptionFailedException::class, $refusal);
            static::assertNull($refusal->getPrevious(), 'A refusal of the KMS carries the error AWS answered.');
        }
    }

    #[Test]
    public function theKeyOfTheTenantIsSymmetricAndEncryptsOnly(): void
    {
        // When
        $key = $this->describeKey(self::ALIAS);

        // Then
        static::assertSame('SYMMETRIC_DEFAULT', $key['KeySpec'] ?? null);
        static::assertSame('ENCRYPT_DECRYPT', $key['KeyUsage'] ?? null);
        static::assertSame('Enabled', $key['KeyState'] ?? null);
        static::assertSame('AWS_KMS', $key['Origin'] ?? null);
    }

    private static function aSealedKey(): string
    {
        $rotated = self::service('test.beffroi.key_take_over', KeyTakeOver::class)->rotate(self::tenant(), Algorithms::rs256(), self::context());

        return self::sealedPrivateJwkOf($rotated);
    }

    private static function sealedPrivateJwkOf(TenantKey $key): string
    {
        $stored = self::service('test.beffroi.keys', TenantKeyRepositoryInterface::class)
            ->find(self::tenant(), $key->kid) ?? static::fail('The key is stored.');

        return $stored->sealedPrivateJwk;
    }

    private function kms(): KmsClient
    {
        return new KmsClient(Configuration::create([
            'region' => $this->option('region'),
            'accessKeyId' => (string) $this->dsn->user,
            'accessKeySecret' => (string) $this->dsn->password,
            'endpoint' => $this->endpoint(),
        ]));
    }

    /**
     * Sends DescribeKey by hand: async-aws/kms does not expose it.
     *
     * @return array<mixed>
     */
    private function describeKey(string $keyId): array
    {
        $response = HttpClient::create()->request('POST', $this->endpoint(), [
            'headers' => [
                'Content-Type' => 'application/x-amz-json-1.1',
                'X-Amz-Target' => 'TrentService.DescribeKey',
                'Authorization' => sprintf(
                    'AWS4-HMAC-SHA256 Credential=%s/20260101/%s/kms/aws4_request, SignedHeaders=host, Signature=unsigned',
                    (string) $this->dsn->user,
                    $this->option('region'),
                ),
            ],
            'json' => [
                'KeyId' => $keyId,
            ],
        ]);
        static::assertSame(200, $response->getStatusCode(), $response->getContent(false));
        $metadata = $response->toArray()['KeyMetadata'] ?? null;
        static::assertIsArray($metadata);

        return $metadata;
    }

    private function endpoint(): string
    {
        return sprintf('%s://%s%s', $this->option('scheme', 'https'), (string) $this->dsn->host, $this->dsn->port === null ? '' : ':' . $this->dsn->port);
    }

    private function option(string $name, string $default = ''): string
    {
        $value = $this->dsn->getOption($name, $default);

        return is_string($value) ? $value : $default;
    }
}
