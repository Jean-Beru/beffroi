<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Key;

use App\Key\FileMailSigningKeyRepository;
use App\Tests\Symfony\Fixture\MailSigningKeys;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use function bin2hex;
use DateTimeImmutable;
use function file_get_contents;
use function glob;
use function implode;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function random_bytes;
use Symfony\Component\Process\Process;
use function sys_get_temp_dir;

/**
 * Architecture §3.3: the mail signing keys of a tenant are files beside its other keys.
 */
final class FileMailSigningKeyRepositoryTest extends TestCase
{
    private string $directory;

    private Tenant $tenant;

    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir() . '/mail-keys-' . bin2hex(random_bytes(4));
        $this->tenant = Fixtures::tenant();
    }

    protected function tearDown(): void
    {
        new Process(['rm', '-rf', $this->directory])->run();
    }

    #[Test]
    public function aKeyIsReadBackAsItWasWritten(): void
    {
        // Given
        $key = MailSigningKeys::smime($this->tenant);

        // When
        new FileMailSigningKeyRepository($this->directory)->save($key);

        // Then
        static::assertEquals($key, new FileMailSigningKeyRepository($this->directory)->current($this->tenant, 'smime'));
    }

    #[Test]
    public function theFileHoldsThePrivateHalfSealedAndNeverInClear(): void
    {
        // Given
        $key = MailSigningKeys::smime($this->tenant);
        $private = Keys::sealer()->unseal($this->tenant, $key->sealedPrivateJwk);

        // When
        new FileMailSigningKeyRepository($this->directory)->save($key);

        // Then
        $files = (array) glob($this->directory . '/acme/mail/*.json');
        static::assertCount(1, $files);
        static::assertStringNotContainsString($private['d'], (string) file_get_contents((string) $files[0]));
    }

    #[Test]
    public function theCurrentKeyIsTheNewestOfItsFormatThatWasNotReplaced(): void
    {
        // Given
        $repository = new FileMailSigningKeyRepository($this->directory);
        $replaced = MailSigningKeys::smime($this->tenant, 'sender', new DateTimeImmutable('2026-11-01T10:00:00+00:00'));
        $replaced->replace(new DateTimeImmutable('2026-11-20T10:00:00+00:00'));
        $current = MailSigningKeys::smime($this->tenant, 'sender-next', new DateTimeImmutable('2026-11-20T10:00:00+00:00'));
        $repository->save($replaced);
        $repository->save($current);

        // When
        $found = $repository->ofKind($this->tenant, 'smime');

        // Then
        static::assertSame(
            [$current->fingerprint, $replaced->fingerprint],
            [$found[0]->fingerprint, $found[1]->fingerprint],
        );
        static::assertSame($current->fingerprint, $repository->current($this->tenant, 'smime')?->fingerprint);
    }

    #[Test]
    public function aRemovedKeyIsReadNoMore(): void
    {
        // Given
        $repository = new FileMailSigningKeyRepository($this->directory);
        $key = MailSigningKeys::pgp($this->tenant);
        $repository->save($key);

        // When
        $repository->remove($key);

        // Then
        static::assertSame([], $repository->ofKind($this->tenant, 'pgp'));
    }

    #[Test]
    public function aFormatThatIsNoWordReadsNothing(): void
    {
        // Given
        $repository = new FileMailSigningKeyRepository($this->directory);
        $repository->save(MailSigningKeys::smime($this->tenant));

        // When / Then
        static::assertSame([], $repository->ofKind($this->tenant, '*'));
    }

    #[Test]
    public function aFileOfAnotherTenantUnderTheSameSlugIsRefused(): void
    {
        // Given
        new FileMailSigningKeyRepository($this->directory)->save(MailSigningKeys::smime(Fixtures::tenant()));

        // Then
        $this->expectException(RuntimeException::class);

        // When
        new FileMailSigningKeyRepository($this->directory)->ofKind($this->tenant, 'smime');
    }

    #[Test]
    public function theKeysAreWrittenWhereTheReaderOfTheTenantKeysLooksForNone(): void
    {
        // When
        new FileMailSigningKeyRepository($this->directory)->save(MailSigningKeys::pgp($this->tenant));

        // Then
        static::assertSame('', implode(',', (array) glob($this->directory . '/acme/*.json')));
    }
}
