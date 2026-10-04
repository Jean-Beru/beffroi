<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Archive;

use Beffroi\Bundle\Archive\ZipArchiveContainer;
use Beffroi\Core\Domain\Archive\ArchivePassword;
use function file_put_contents;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use function sys_get_temp_dir;
use function tempnam;
use function unlink;
use ZipArchive;

/**
 * Issue #483: the archive of a person wrapped in a zip whose single entry is encrypted with AES-256, and
 * what that container does and does not hide.
 */
final class ZipArchiveContainerTest extends TestCase
{
    private const string DOCUMENT = '{"profile":[{"username":"ada-lovelace","email":"ada@example.org"}]}';

    private const string NAME = 'archive-0199cf3e-0000-7000-8000-000000000000.json';

    #[Test]
    public function theDocumentIsReadBackUnderThePassphraseItWasWrappedWith(): void
    {
        // Given
        $passphrase = self::passphrase();

        // When
        $wrapped = new ZipArchiveContainer()->wrap(self::DOCUMENT, self::NAME, $passphrase);

        // Then
        static::assertSame(self::DOCUMENT, self::read($wrapped, $passphrase->value));
    }

    /**
     * The whole point of the container: what a person downloaded says nothing of them to whoever ends up
     * holding it. The entry is encrypted, so the bytes carry neither the values nor the names of the
     * document.
     */
    #[Test]
    public function theWrappedFileCarriesNothingOfTheDocumentInTheClear(): void
    {
        // When
        $wrapped = new ZipArchiveContainer()->wrap(self::DOCUMENT, self::NAME, self::passphrase());

        // Then
        static::assertStringNotContainsString('ada-lovelace', $wrapped);
        static::assertStringNotContainsString('ada@example.org', $wrapped);
        static::assertStringNotContainsString('username', $wrapped);
    }

    #[Test]
    public function anotherPassphraseDoesNotOpenIt(): void
    {
        // Given
        $wrapped = new ZipArchiveContainer()->wrap(self::DOCUMENT, self::NAME, self::passphrase());

        // When
        $read = self::read($wrapped, 'a passphrase nobody chose');

        // Then
        static::assertFalse($read);
    }

    /**
     * What a zip leaves readable is the name of its entry, which is the name of the archive and names no
     * person: it is a line of the page for whoever reads one and not a defect to hide.
     */
    #[Test]
    public function theNameOfTheEntryStaysReadableAndNamesNoPerson(): void
    {
        // When
        $wrapped = new ZipArchiveContainer()->wrap(self::DOCUMENT, self::NAME, self::passphrase());

        // Then
        static::assertStringContainsString(self::NAME, $wrapped);
    }

    #[Test]
    public function theContainerSaysWhatItWrites(): void
    {
        // Given
        $container = new ZipArchiveContainer();

        // When / Then
        static::assertSame('application/zip', $container->mediaType());
        static::assertSame('zip', $container->extension());
    }

    private static function passphrase(): ArchivePassword
    {
        return new ArchivePassword('correct horse battery staple');
    }

    /**
     * The entry read back the way whoever downloaded the file reads it, by a tool that knows the format
     * and the passphrase, and false when that passphrase does not open it.
     */
    private static function read(string $wrapped, string $passphrase): string|false
    {
        $path = tempnam(sys_get_temp_dir(), 'beffroi-read-');
        if ($path === false) {
            static::fail('No temporary file could be opened.');
        }
        file_put_contents($path, $wrapped);

        try {
            $zip = new ZipArchive();
            static::assertTrue($zip->open($path));
            $zip->setPassword($passphrase);
            $read = $zip->getFromName(self::NAME);
            $zip->close();

            return $read;
        } finally {
            unlink($path);
        }
    }

    /**
     * The upper bound of a passphrase is not a bound on the document: an archive of a person who has a
     * long history is megabytes, and the container writes it.
     */
    #[Test]
    public function aLongDocumentIsWrappedAndReadBack(): void
    {
        // Given
        $document = str_repeat(self::DOCUMENT, 20_000);
        $passphrase = self::passphrase();

        // When
        $wrapped = new ZipArchiveContainer()->wrap($document, self::NAME, $passphrase);

        // Then
        static::assertSame($document, self::read($wrapped, $passphrase->value));
    }
}
