<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Key;

use Beffroi\Tui\Key\PemFile;
use Beffroi\Tui\Key\PemFileException;
use function chmod;
use function dirname;
use function file_put_contents;
use function is_file;
use function mkdir;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function rmdir;
use function sprintf;
use function str_repeat;
use function sys_get_temp_dir;
use function uniqid;
use function unlink;

/**
 * Decision 0051: the S/MIME key of a tenant is sent from two files in PEM the administrator names, read on their machine.
 */
final class PemFileTest extends TestCase
{
    private const string KEY = "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n";

    private string $file;

    protected function setUp(): void
    {
        $directory = sprintf('%s/beffroi-tui-pem-%s', sys_get_temp_dir(), uniqid());
        mkdir($directory, 0o700);
        $this->file = $directory . '/mail.pem';
        file_put_contents($this->file, self::KEY);
        chmod($this->file, 0o600);
    }

    protected function tearDown(): void
    {
        if (is_file($this->file)) {
            unlink($this->file);
        }
        rmdir(dirname($this->file));
    }

    #[Test]
    public function aPrivateKeyOnlyItsOwnerMayOpenIsReadAsWritten(): void
    {
        // When
        $key = PemFile::privateKey($this->file);

        // Then
        static::assertSame(self::KEY, $key->contents);
    }

    /**
     * A certificate and its chain are public: whoever reads them learns nothing a signature does not carry.
     */
    #[Test]
    public function certificatesOthersMayReadAreRead(): void
    {
        // Given
        chmod($this->file, 0o644);

        // When
        $certificates = PemFile::certificates($this->file);

        // Then
        static::assertSame(self::KEY, $certificates->contents);
    }

    #[Test]
    #[DataProvider('provideOpenings')]
    public function aPrivateKeyTheGroupOrOthersMayOpenIsRefused(int $permissions): void
    {
        // Given
        chmod($this->file, $permissions);

        // Then
        $this->expectException(PemFileException::class);
        $this->expectExceptionMessageIs(sprintf(
            'Others may open the private key %s: it is not read until "chmod 600 %s" closes it.',
            $this->file,
            $this->file,
        ));

        // When
        PemFile::privateKey($this->file);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideOpenings(): iterable
    {
        yield 'read by the group' => [0o640];
        yield 'read by others' => [0o604];
        yield 'written by the group' => [0o620];
        yield 'run by others' => [0o601];
    }

    #[Test]
    #[DataProvider('providePathsOfNoFile')]
    public function aPathThatNamesNoFileThatCanBeReadIsRefused(string $suffix): void
    {
        // Given
        $path = dirname($this->file) . $suffix;

        // Then
        $this->expectException(PemFileException::class);
        $this->expectExceptionMessageIs(sprintf('"%s" is not a file that can be read.', $path));

        // When
        PemFile::certificates($path);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function providePathsOfNoFile(): iterable
    {
        yield 'a file that is not there' => ['/absent.pem'];
        yield 'a directory' => [''];
    }

    #[Test]
    public function aFileOfTheLimitIsReadWhole(): void
    {
        // Given
        file_put_contents($this->file, str_repeat('A', PemFile::LIMIT));

        // When
        $certificates = PemFile::certificates($this->file);

        // Then
        static::assertSame(str_repeat('A', PemFile::LIMIT), $certificates->contents);
    }

    #[Test]
    public function aFileLargerThanTheLimitIsRefused(): void
    {
        // Given
        file_put_contents($this->file, str_repeat('A', PemFile::LIMIT + 1));

        // Then
        $this->expectException(PemFileException::class);
        $this->expectExceptionMessageIs(sprintf('"%s" holds more than %d bytes.', $this->file, PemFile::LIMIT));

        // When
        PemFile::certificates($this->file);
    }
}
