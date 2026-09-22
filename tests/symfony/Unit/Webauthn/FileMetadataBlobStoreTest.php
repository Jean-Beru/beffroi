<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Webauthn;

use function file_get_contents;
use Heidi\Bundle\Webauthn\FileMetadataBlobStore;
use Heidi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use function sys_get_temp_dir;
use function uniqid;

/**
 * The FIDO metadata as files (architecture §3.4): one document per name, read in the order of the names.
 */
final class FileMetadataBlobStoreTest extends TestCase
{
    private string $directory;

    private FileMetadataBlobStore $store;

    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir() . '/heidi-bundle-tests/webauthn-' . uniqid();
        $this->store = new FileMetadataBlobStore($this->directory);
    }

    protected function tearDown(): void
    {
        new Filesystem()->remove($this->directory);
    }

    #[Test]
    public function aDocumentIsWrittenUnderItsNameInADirectoryCreatedOnTheWay(): void
    {
        // When
        $this->store->write('mds-mds.fidoalliance.org-3f2a9b1c', '{"no": 1}');

        // Then
        static::assertDirectoryExists($this->directory);
        static::assertSame('{"no": 1}', file_get_contents($this->directory . '/mds-mds.fidoalliance.org-3f2a9b1c.json'));
    }

    #[Test]
    public function theDocumentsAreReadByNameInTheOrderOfTheNames(): void
    {
        // Given
        $this->store->write('statement-b', '{"no": 2}');
        $this->store->write('mds-a', '{"no": 1}');

        // When
        $documents = $this->store->readAll();

        // Then
        static::assertSame(
            [
                'mds-a' => '{"no": 1}',
                'statement-b' => '{"no": 2}',
            ],
            $documents,
        );
    }

    #[Test]
    public function aDocumentWrittenAgainReplacesTheOneOfItsName(): void
    {
        // Given
        $this->store->write('mds-a', '{"no": 1}');

        // When
        $this->store->write('mds-a', '{"no": 2}');

        // Then
        static::assertSame(
            [
                'mds-a' => '{"no": 2}',
            ],
            $this->store->readAll(),
        );
    }

    #[Test]
    public function anEmptyStoreReadsNothing(): void
    {
        // When / Then
        static::assertSame([], $this->store->readAll());
    }

    /**
     * @param non-empty-string $name
     */
    #[Test]
    #[DataProvider('provideNamesThatCannotNameAFile')]
    public function aNameOutsideOfTheAlphabetIsRefused(string $name): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('cannot name a metadata document');

        // When
        $this->store->write($name, '{}');
    }

    /**
     * @return iterable<string, array{non-empty-string}>
     */
    public static function provideNamesThatCannotNameAFile(): iterable
    {
        yield 'a path' => ['../keys/acme'];
        yield 'a slash' => ['mds/a'];
        yield 'a space' => ['mds a'];
        yield 'a name after junk' => ['!mds'];
        yield 'junk after a name' => ['mds!'];
        yield 'a trailing newline' => ["mds\n"];
    }
}
