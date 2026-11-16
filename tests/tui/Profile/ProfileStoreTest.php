<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Profile;

use Beffroi\Tui\Key\SigningKey;
use Beffroi\Tui\Profile\ProfileException;
use Beffroi\Tui\Profile\ProfileStore;
use Beffroi\Tui\Tests\Fixture\FakeProvider;
use function chmod;
use function clearstatcache;
use function dirname;
use function fileperms;
use function glob;
use function json_encode;
use function json_decode;
use function file_put_contents;
use function file_get_contents;
use const GLOB_BRACE;
use function is_dir;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function rmdir;
use function sprintf;
use function sys_get_temp_dir;
use function uniqid;
use function unlink;

/**
 * A profile holds the private key of a client: it is written readable by its owner alone, read only while it
 * stays so, and never written over.
 */
final class ProfileStoreTest extends TestCase
{
    private string $directory;

    protected function setUp(): void
    {
        $this->directory = sprintf('%s/beffroi-tui-%s/beffroi/tui', sys_get_temp_dir(), uniqid());
    }

    protected function tearDown(): void
    {
        $files = glob($this->directory . '/{,.}*.json', GLOB_BRACE);
        foreach ($files === false ? [] : $files as $file) {
            unlink($file);
        }
        if (is_dir($this->directory)) {
            rmdir($this->directory);
            rmdir(dirname($this->directory));
            rmdir(dirname($this->directory, 2));
        }
    }

    #[Test]
    public function aProfileIsWrittenReadableByItsOwnerAlone(): void
    {
        // Given
        $store = new ProfileStore($this->directory);

        // When
        $path = $store->save('dev', FakeProvider::profile(SigningKey::generate()));

        // Then
        clearstatcache();
        static::assertSame([0o600, 0o700], [fileperms($path) & 0o777, fileperms($this->directory) & 0o777]);
    }

    #[Test]
    public function aProfileIsReadBackAsItWasWritten(): void
    {
        // Given
        $store = new ProfileStore($this->directory);
        $profile = FakeProvider::profile(SigningKey::generate());
        $store->save('dev', $profile);

        // When
        $loaded = $store->load('dev');

        // Then
        static::assertSame($profile->toDocument(), $loaded->toDocument());
    }

    /**
     * Decision 0038: whether the person may administer the instance is what the provider answers for its
     * administration API, so a profile that names none is not used.
     */
    #[Test]
    public function aProfileThatNamesNoAdministrationApiIsNotUsed(): void
    {
        // Given
        $store = new ProfileStore($this->directory);
        $path = $store->save('dev', FakeProvider::profile(SigningKey::generate()));
        $document = json_decode((string) file_get_contents($path), true, 16, JSON_THROW_ON_ERROR);
        static::assertIsArray($document);
        unset($document['administration']);
        file_put_contents($path, json_encode($document, JSON_THROW_ON_ERROR));

        // Then
        $this->expectException(ProfileException::class);
        $this->expectExceptionMessageIsOrContains('it names no administration API, as a profile registered before this program asked for one does: register this machine again');

        // When
        $store->load('dev');
    }

    #[Test]
    public function aProfileOthersMayOpenIsNotRead(): void
    {
        // Given
        $store = new ProfileStore($this->directory);
        $path = $store->save('dev', FakeProvider::profile(SigningKey::generate()));
        chmod($path, 0o640);

        // Then
        $this->expectException(ProfileException::class);
        $this->expectExceptionMessageIs(sprintf(
            'The profile %s holds the private key of a client and others may open it: it is not read until "chmod 600 %s" closes it.',
            $path,
            $path,
        ));

        // When
        $store->load('dev');
    }

    #[Test]
    public function aProfileIsNeverWrittenOver(): void
    {
        // Given
        $store = new ProfileStore($this->directory);
        $store->save('dev', FakeProvider::profile(SigningKey::generate()));

        // Then
        $this->expectException(ProfileException::class);

        // When
        $store->save('dev', FakeProvider::profile(SigningKey::generate()));
    }

    #[Test]
    #[DataProvider('provideNamesNoFileIsNamedAfter')]
    public function aProfileIsNamedLikeAFile(string $name): void
    {
        // Then
        $this->expectException(ProfileException::class);

        // When
        new ProfileStore($this->directory)->path($name);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNamesNoFileIsNamedAfter(): iterable
    {
        yield 'a path' => ['../ssh/id_ed25519'];
        yield 'a hidden file' => ['.dev'];
        yield 'empty' => [''];
        yield 'uppercase' => ['Dev'];
    }

    /**
     * @param array<string, string> $environment
     */
    #[Test]
    #[DataProvider('provideEnvironments')]
    public function theProfilesAreKeptInTheConfigurationHome(array $environment, string $path): void
    {
        // When / Then
        static::assertSame($path, ProfileStore::inConfigurationHome($environment)->path('dev'));
    }

    /**
     * @return iterable<string, array{array<string, string>, string}>
     */
    public static function provideEnvironments(): iterable
    {
        yield 'XDG_CONFIG_HOME' => [['XDG_CONFIG_HOME' => '/home/admin/.cfg', 'HOME' => '/home/admin'], '/home/admin/.cfg/beffroi/tui/dev.json'];
        yield 'HOME when XDG_CONFIG_HOME is not set' => [['HOME' => '/home/admin/'], '/home/admin/.config/beffroi/tui/dev.json'];
        yield 'HOME when XDG_CONFIG_HOME is relative' => [['XDG_CONFIG_HOME' => 'cfg', 'HOME' => '/home/admin'], '/home/admin/.config/beffroi/tui/dev.json'];
    }
}
