<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Key;

use AsyncAws\Core\Configuration;
use AsyncAws\Core\Exception\Http\ClientException;
use AsyncAws\Kms\Input\DecryptRequest;
use AsyncAws\Kms\KmsClient;
use function base64_encode;
use function getenv;
use App\Tests\Symfony\Functional\Doctrine\DatabaseTestCase;
use Beffroi\Core\Application\Key\KeyTakeOver;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Port\TenantKeyRepositoryInterface;
use Beffroi\Core\Tests\Fixture\Algorithms;
use function is_string;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use function str_starts_with;
use function strlen;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\KeyManagement\Dsn;
use Symfony\Component\KeyManagement\Envelope;

/**
 * Issue #58, against an AWS KMS (LocalStack on the development stack, the same API): the master key of the
 * tenant is the one docker/localstack/init.sh creates under the alias the DSN names, and the envelope holds
 * the data key as that KMS wrapped it, bound to the tenant. Skipped unless the kernel seals with AWS KMS
 * (BEFFROI_TEST_KMS_DSN), which no job of the CI does and which "castor phpunit" does not pass to its
 * container: it is run by hand, BEFFROI_TEST_KMS_DSN naming the LocalStack of the development stack
 * ("castor start --kms aws") and BEFFROI_TEST_KMS_KEY_ID its alias ("alias/beffroi-{tenant}"), and every
 * other test of that run then seals with that KMS too.
 */
final class AwsKmsCustodyTest extends DatabaseTestCase
{
    private const string SCHEME = 'aws-kms://';

    private const string ALIAS = 'alias/beffroi-default';

    private const string AAD = 'beffroi:signing-key:v2:default';

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

    /**
     * The envelope of a sealed key names the alias of the tenant and carries a data key the KMS wrapped
     * under it: what the KMS hands back, with the context the envelope bound, is the 32 bytes of the data
     * key, never the private JWK, which stayed in the process.
     */
    #[Test]
    public function theDataKeyOfASealedKeyIsWrappedByTheKeyOfTheTenant(): void
    {
        // Given
        $takeOver = self::service('test.beffroi.key_take_over', KeyTakeOver::class);

        // When
        $rotated = $takeOver->rotate(self::tenant(), Algorithms::rs256(), self::context());

        // Then
        $envelope = self::envelopeOf($rotated);
        static::assertSame(self::ALIAS, $envelope->keyId);
        static::assertIsString($envelope->wrappedDek);
        $unwrapped = $this->kms()->decrypt(new DecryptRequest([
            'KeyId' => self::ALIAS,
            'CiphertextBlob' => $envelope->wrappedDek,
            'EncryptionContext' => [
                'aad' => base64_encode(self::AAD),
            ],
        ]));
        static::assertSame(32, strlen((string) $unwrapped->getPlaintext()));
        static::assertStringContainsString(':key/', (string) $unwrapped->getKeyId());
    }

    /**
     * The binding to the tenant is enforced by the KMS itself: the data key does not unwrap under the
     * context of another tenant, whoever holds the credential.
     */
    #[Test]
    public function theKmsRefusesToUnwrapTheDataKeyUnderAnotherTenant(): void
    {
        // Given
        $rotated = self::service('test.beffroi.key_take_over', KeyTakeOver::class)->rotate(self::tenant(), Algorithms::rs256(), self::context());
        $envelope = self::envelopeOf($rotated);

        // Then
        $this->expectException(ClientException::class);
        $this->expectExceptionMessageIsOrContains('InvalidCiphertextException');

        // When
        $this->kms()
            ->decrypt(new DecryptRequest([
                'KeyId' => self::ALIAS,
                'CiphertextBlob' => (string) $envelope->wrappedDek,
                'EncryptionContext' => [
                    'aad' => base64_encode('beffroi:signing-key:v2:other'),
                ],
            ]))
            ->getPlaintext();
    }

    /**
     * The key docker/localstack/init.sh creates: symmetric, for encryption only, enabled, behind the alias
     * the OP names, so that a new key behind the same alias changes nothing for it.
     */
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

    private static function envelopeOf(TenantKey $key): Envelope
    {
        $stored = self::service('test.beffroi.keys', TenantKeyRepositoryInterface::class)
            ->find(self::tenant(), $key->kid) ?? static::fail('The key is stored.');

        return Envelope::fromBytes($stored->sealedPrivateJwk);
    }

    /**
     * A client on the KMS of the DSN, as the bridge builds it: the region from the option, the credentials
     * from the user information, the host as the endpoint over the scheme of the option.
     */
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
     * DescribeKey, which async-aws/kms does not expose: the JSON protocol of KMS, the target in a header.
     * The credential of the DSN names the region and the account, which is all LocalStack reads of it.
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
