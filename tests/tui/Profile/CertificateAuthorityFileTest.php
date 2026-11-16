<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Profile;

use Beffroi\Tui\Profile\CertificateAuthorityFile;
use Beffroi\Tui\Profile\ProfileException;
use function chdir;
use function chmod;
use function dirname;
use function file_put_contents;
use function getcwd;
use function mkdir;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function rmdir;
use function sprintf;
use function sys_get_temp_dir;
use function uniqid;
use function unlink;

/**
 * The certificate authorities an instance is trusted under are a file nobody else may write.
 */
final class CertificateAuthorityFileTest extends TestCase
{
    private string $file;

    protected function setUp(): void
    {
        $directory = sprintf('%s/beffroi-tui-ca-%s', sys_get_temp_dir(), uniqid());
        mkdir($directory, 0o700);
        $this->file = $directory . '/root.crt';
        file_put_contents($this->file, "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n");
    }

    protected function tearDown(): void
    {
        unlink($this->file);
        rmdir(dirname($this->file));
    }

    #[Test]
    public function aFileIsKeptByItsAbsolutePath(): void
    {
        // Given
        chmod($this->file, 0o644);
        $directory = (string) getcwd();
        chdir(dirname($this->file));

        // When
        try {
            $path = CertificateAuthorityFile::at('root.crt');
        } finally {
            chdir($directory);
        }

        // Then
        static::assertSame($this->file, $path);
    }

    #[Test]
    public function aFileOthersMayWriteIsNotTrusted(): void
    {
        // Given
        chmod($this->file, 0o664);

        // Then
        $this->expectException(ProfileException::class);
        $this->expectExceptionMessageIs(sprintf(
            'Others may write the certificate authorities of %s, which an instance is trusted under: they are not trusted until "chmod go-w %s" closes it.',
            $this->file,
            $this->file,
        ));

        // When
        CertificateAuthorityFile::at($this->file);
    }

    #[Test]
    public function aFileThatIsNotThereIsNotTrusted(): void
    {
        // Then
        $this->expectException(ProfileException::class);

        // When
        CertificateAuthorityFile::at($this->file . '.missing');
    }
}
