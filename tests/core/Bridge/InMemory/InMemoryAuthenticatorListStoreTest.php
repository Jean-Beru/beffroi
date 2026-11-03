<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\InMemory;

use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticatorListStore;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The port of the store of the list of the community as the tests of the core see it: one document, replaced by
 * the next one, nothing until one is written.
 */
final class InMemoryAuthenticatorListStoreTest extends TestCase
{
    #[Test]
    public function nothingIsReadBeforeAListIsWritten(): void
    {
        // When / Then
        static::assertNull(new InMemoryAuthenticatorListStore()->read());
    }

    #[Test]
    public function aListWrittenReplacesTheOneStored(): void
    {
        // Given
        $store = new InMemoryAuthenticatorListStore();
        $store->write('{"first": {}}');

        // When
        $store->write('{"second": {}}');

        // Then
        static::assertSame('{"second": {}}', $store->read());
    }
}
