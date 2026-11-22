<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Webauthn;

use function file_get_contents;
use App\Webauthn\FileAuthenticatorListStore;
use function fileperms;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use function sys_get_temp_dir;
use function uniqid;

/**
 * Architecture §3.4
 */
final class FileAuthenticatorListStoreTest extends TestCase
{
    private string $storage;

    private string $directory;

    private FileAuthenticatorListStore $store;

    protected function setUp(): void
    {
        $this->storage = sys_get_temp_dir() . '/beffroi-integration-tests/webauthn-' . uniqid();
        $this->directory = $this->storage . '/community';
        $this->store = new FileAuthenticatorListStore($this->directory);
    }

    protected function tearDown(): void
    {
        new Filesystem()->remove($this->storage);
    }

    #[Test]
    public function theListIsWrittenInADirectoryCreatedOnTheWay(): void
    {
        // When
        $this->store->write('{"list": 1}');

        // Then
        static::assertSame('{"list": 1}', file_get_contents($this->directory . '/authenticators.json'));
    }

    #[Test]
    public function theListIsReadByItsOwnerAlone(): void
    {
        // When
        $this->store->write('{"list": 1}');

        // Then
        static::assertSame(0o600, fileperms($this->directory . '/authenticators.json') & 0o777);
    }

    #[Test]
    public function aListWrittenAgainReplacesTheStoredOne(): void
    {
        // Given
        $this->store->write('{"list": 1}');

        // When
        $this->store->write('{"list": 2}');

        // Then
        static::assertSame('{"list": 2}', $this->store->read());
    }

    #[Test]
    public function nothingIsReadWhereNoListWasWritten(): void
    {
        // When / Then
        static::assertNull($this->store->read());
    }
}
