<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Key;

use function array_keys;
use function array_map;
use function base64_decode;
use DateInterval;
use function explode;
use Heidi\Bundle\Key\FileTenantKeyRepository;
use Heidi\Bundle\Tests\Functional\Doctrine\DatabaseTestCase;
use Heidi\Core\Application\Key\TenantKeyRotator;
use Heidi\Core\Domain\Key\TenantKey;
use Heidi\Core\Port\JwsSignerInterface;
use Heidi\Core\Port\KeyPairGeneratorInterface;
use Heidi\Core\Port\KeySealerInterface;
use Heidi\Core\Port\PublicKeySetProviderInterface;
use Heidi\Core\Port\SigningKeyProviderInterface;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use ReflectionProperty;
use function strtr;
use Symfony\Component\Clock\NativeClock;
use Symfony\Component\Filesystem\Filesystem;

/**
 * Architecture §3.3: the provider the kernel holds is one object for the life of the process, which in
 * a FrankenPHP worker is every request the worker serves. A rotation is done by another process, a
 * console command or a scheduled step, that shares nothing with the worker but the key files. The
 * worker must see it without a restart: the provider reads which key is active on each call and keeps
 * only the opened material, by "kid". Proven here with a second repository on the same directory, as
 * another process would have; the kernel is not rebooted between the steps.
 */
final class SealedKeyProviderTest extends DatabaseTestCase
{
    private string $directory;

    private SigningKeyProviderInterface $provider;

    private PublicKeySetProviderInterface $published;

    protected function setUp(): void
    {
        parent::setUp();
        $cacheDir = self::getContainer()->getParameter('kernel.cache_dir');
        static::assertIsString($cacheDir);
        $this->directory = $cacheDir . '/keys';
        new Filesystem()->remove($this->directory);
        $this->provider = self::service('test.heidi.key_provider', SigningKeyProviderInterface::class);
        $this->published = self::service('test.heidi.public_keys', PublicKeySetProviderInterface::class);
        self::service('test.heidi.key_rotator', TenantKeyRotator::class)->rotate(self::tenant(), Algorithms::rs256(), self::context());
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        new Filesystem()->remove($this->directory);
    }

    /**
     * The key that signs is the one another process activated, seen by the provider that had already
     * opened the previous one.
     */
    #[Test]
    public function aRotationDoneByAnotherProcessIsSeenWithoutARestart(): void
    {
        // Given
        $opened = $this->provider->activeKey(self::tenant(), Algorithms::rs256());
        $rotated = $this->rotateFromAnotherProcess();

        // When
        $active = $this->provider->activeKey(self::tenant(), Algorithms::rs256());

        // Then
        static::assertNotSame($opened->key->kid, $rotated->kid);
        static::assertSame($rotated->kid, $active->key->kid);
    }

    /**
     * What the worker signs after the rotation names the new key, through the signer the modules use.
     */
    #[Test]
    public function theWorkerSignsWithTheNewKeyAtOnce(): void
    {
        // Given
        $signer = self::service('test.heidi.jws_signer', JwsSignerInterface::class);
        $signer->sign(self::tenant(), Algorithms::rs256(), 'before');
        $rotated = $this->rotateFromAnotherProcess();

        // When
        $jws = $signer->sign(self::tenant(), Algorithms::rs256(), 'after');

        // Then
        static::assertStringContainsString($rotated->kid, self::header($jws));
    }

    /**
     * The JWK Set the worker serves after the rotation carries both keys, the retiring one and the new
     * one, without a restart.
     */
    #[Test]
    public function theWorkerPublishesBothKeysAtOnce(): void
    {
        // Given
        $previous = $this->provider->activeKey(self::tenant(), Algorithms::rs256())->key;
        $rotated = $this->rotateFromAnotherProcess();

        // When
        $published = $this->published->publicKeys(self::tenant());

        // Then
        static::assertSame([$previous->kid, $rotated->kid], array_map(static fn (TenantKey $key): string => $key->kid, $published->keys));
    }

    /**
     * The provider keeps the opened material of the key that signs and no other: the previous one is
     * out of the memory of the worker once the rotation is seen.
     */
    #[Test]
    public function theWorkerForgetsThePreviousKeyOnceTheRotationIsSeen(): void
    {
        // Given
        $this->provider->activeKey(self::tenant(), Algorithms::rs256());
        $rotated = $this->rotateFromAnotherProcess();

        // When
        $this->provider->activeKey(self::tenant(), Algorithms::rs256());

        // Then
        $opened = new ReflectionProperty($this->provider, 'opened')->getValue($this->provider);
        static::assertIsArray($opened);
        static::assertSame([$rotated->kid], array_keys($opened));
    }

    /**
     * A rotation as a console command does it: a repository of its own on the same files, a rotator of
     * its own, nothing shared with the provider under test but the directory.
     */
    private function rotateFromAnotherProcess(): TenantKey
    {
        $rotator = new TenantKeyRotator(
            new FileTenantKeyRepository($this->directory, Algorithms::all()),
            self::service('test.heidi.key_pair_generator', KeyPairGeneratorInterface::class),
            self::service('test.heidi.key_sealer', KeySealerInterface::class),
            [],
            new DateInterval('PT6M'),
            new NativeClock(),
            new RecordingEventDispatcher(),
        );

        return $rotator->rotate(self::tenant(), Algorithms::rs256(), self::context());
    }

    /**
     * The protected header of a compact JWS, decoded.
     */
    private static function header(string $compactJws): string
    {
        $decoded = base64_decode(strtr(explode('.', $compactJws)[0], '-_', '+/'), true);
        static::assertIsString($decoded);

        return $decoded;
    }
}
