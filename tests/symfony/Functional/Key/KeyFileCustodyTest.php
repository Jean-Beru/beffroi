<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Key;

use function dirname;
use function fileperms;
use function filesize;
use function getenv;
use Beffroi\Bundle\Tests\Functional\Doctrine\DatabaseTestCase;
use Beffroi\Core\Application\Key\TenantKeyRotator;
use Beffroi\Core\Port\TenantKeyRepositoryInterface;
use Beffroi\Core\Tests\Fixture\Algorithms;
use function is_string;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use function str_starts_with;
use Symfony\Component\Filesystem\Path;
use Symfony\Component\KeyManagement\Dsn;
use Symfony\Component\KeyManagement\Envelope;

/**
 * Issue #58, the file backend: the same sodium backend as the development default, its key read from a
 * file of its own instead of the environment (FilesystemKeyLoader, "sodium+dir://<directory>?ext=.key"),
 * one file per tenant. Skipped unless the kernel seals with it (BEFFROI_TEST_KMS_DSN), which the CI does in
 * a job of its own with a key written the way "castor provision --kms file" writes it; every other test of
 * the suite then runs against it too.
 */
final class KeyFileCustodyTest extends DatabaseTestCase
{
    private const string SCHEME = 'sodium+dir://';

    private const string KEY_ID = 'beffroi-default';

    private Dsn $dsn;

    protected function setUp(): void
    {
        $dsn = getenv('BEFFROI_TEST_KMS_DSN');
        if (! is_string($dsn) || ! str_starts_with($dsn, self::SCHEME)) {
            static::markTestSkipped('The kernel seals with an inline sodium key; set BEFFROI_TEST_KMS_DSN to a sodium+dir DSN to run this test.');
        }
        parent::setUp();
        $this->dsn = Dsn::fromString($dsn);
    }

    /**
     * The envelope of a sealed key names the key file of the tenant, not the key of every tenant.
     */
    #[Test]
    public function aSealedKeyIsWrappedByTheKeyFileOfTheTenant(): void
    {
        // Given
        $rotator = self::service('test.beffroi.key_rotator', TenantKeyRotator::class);

        // When
        $rotated = $rotator->rotate(self::tenant(), Algorithms::rs256(), self::context());

        // Then
        $stored = self::service('test.beffroi.keys', TenantKeyRepositoryInterface::class)
            ->find(self::tenant(), $rotated->kid) ?? static::fail('The key is stored.');
        static::assertSame(self::KEY_ID, Envelope::fromBytes($stored->sealedPrivateJwk)->keyId);
    }

    /**
     * What the CISO page promises of the file: 32 bytes and nothing else, readable by the process alone,
     * in a directory of its own that the sealed keys do not share, so that a dump of the sealed keys is not
     * a dump of what opens them.
     */
    #[Test]
    public function theKeyFileIsReadableByTheProcessAloneAndLivesApartFromTheSealedKeys(): void
    {
        // Given
        $directory = $this->dsn->path;
        $extension = $this->dsn->getOption('ext', '');
        $file = sprintf('%s/%s%s', $directory, self::KEY_ID, is_string($extension) ? $extension : '');
        // the storage of this kernel (config_test.yml): "%kernel.cache_dir%/keys"
        $storage = (self::$kernel ?? static::fail('The kernel is booted.'))->getCacheDir() . '/keys';

        // When / Then
        static::assertFileExists($file);
        static::assertSame(32, filesize($file));
        static::assertSame(0o600, fileperms($file) & 0o777, sprintf('%s is readable by its owner alone.', $file));
        static::assertSame(0o700, fileperms(dirname($file)) & 0o777, sprintf('%s is readable by its owner alone.', $directory));
        static::assertFalse(Path::isBasePath($storage, $file), 'The key file is outside the storage of the sealed keys.');
        static::assertFalse(Path::isBasePath($directory, $storage), 'The sealed keys are outside the directory of the key file.');
    }
}
