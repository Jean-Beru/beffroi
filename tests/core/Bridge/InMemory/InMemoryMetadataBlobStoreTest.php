<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Bridge\InMemory;

use Heidi\Core\Bridge\InMemory\InMemoryMetadataBlobStore;
use Heidi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The port of the metadata store as the tests of the core see it: by name, in the order of the names,
 * the alphabet of a name the one of the file store.
 */
final class InMemoryMetadataBlobStoreTest extends TestCase
{
    #[Test]
    public function theDocumentsAreReadByNameInTheOrderOfTheNames(): void
    {
        // Given
        $store = new InMemoryMetadataBlobStore();
        $store->write('statement-b', '{"no": 2}');
        $store->write('mds-a', '{"no": 1}');

        // When
        $documents = $store->readAll();

        // Then
        static::assertSame(
            [
                'mds-a' => '{"no": 1}',
                'statement-b' => '{"no": 2}',
            ],
            $documents,
        );
    }

    /**
     * @param non-empty-string $name
     */
    #[Test]
    #[DataProvider('provideNamesOutsideOfTheAlphabet')]
    public function aNameOutsideOfTheAlphabetIsRefused(string $name): void
    {
        // Given
        $store = new InMemoryMetadataBlobStore();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('cannot name a metadata document');

        // When
        $store->write($name, '{}');
    }

    /**
     * @return iterable<string, array{non-empty-string}>
     */
    public static function provideNamesOutsideOfTheAlphabet(): iterable
    {
        yield 'a path' => ['../keys/acme'];
        yield 'a name after junk' => ['!mds'];
        yield 'junk after a name' => ['mds!'];
        yield 'a trailing newline' => ["mds\n"];
    }
}
