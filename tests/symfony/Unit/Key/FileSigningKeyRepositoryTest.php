<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Key;

use DateTimeImmutable;
use function decoct;
use function file_put_contents;
use function fileperms;
use function glob;
use Heidi\Bundle\Key\FileSigningKeyRepository;
use Heidi\Core\Domain\Key\KeyStatus;
use Heidi\Core\Domain\Key\SignatureAlgorithm;
use Heidi\Core\Domain\Key\SigningKey;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Exception\RuntimeException;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\Keys;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use function mkdir;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use function sys_get_temp_dir;
use function uniqid;

/**
 * Architecture §3.3: the sealed keys as files, one per key, under the tenant's slug.
 */
final class FileSigningKeyRepositoryTest extends TestCase
{
    private string $directory;

    private FileSigningKeyRepository $repository;

    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir() . '/heidi-keys-' . uniqid('', true);
        $this->repository = new FileSigningKeyRepository($this->directory);
    }

    protected function tearDown(): void
    {
        new Filesystem()
            ->remove($this->directory);
    }

    #[Test]
    public function aSavedKeyIsReadBackWithEverythingItCarries(): void
    {
        $tenant = Fixtures::tenant();
        $key = new SigningKey(Keys::pair()->kid, $tenant, SignatureAlgorithm::RS256, Keys::pair()->publicJwk, Keys::sealer()->seal(Keys::pair()->privateJwk), Fixtures::now());

        $this->repository->save($key);
        $found = $this->repository->find($tenant, $key->kid) ?? static::fail('The key is found.');

        static::assertNotSame($key, $found);
        static::assertSame($key->kid, $found->kid);
        static::assertSame($tenant, $found->tenant);
        static::assertSame('RS256', $found->algorithm->value);
        static::assertSame($key->publicJwk, $found->publicJwk);
        static::assertSame($key->sealedPrivateJwk, $found->sealedPrivateJwk);
        static::assertSame(Keys::pair()->privateJwk, Keys::sealer()->unseal($found->sealedPrivateJwk));
        static::assertEquals(Fixtures::now(), $found->createdAt);
        static::assertSame(KeyStatus::Active, $found->status);
        static::assertNull($found->retiringAt);
        static::assertNull($found->retiredAt);
        static::assertFileExists($this->directory . '/acme/' . $key->kid . '.json');
    }

    #[Test]
    public function theStatusAndItsDatesSurviveTheRoundTrip(): void
    {
        $tenant = Fixtures::tenant();
        $key = self::key($tenant, Keys::pair()->kid);
        $key->startRetiring(Fixtures::now()->modify('+1 day'));
        $this->repository->save($key);

        $retiring = $this->repository->find($tenant, $key->kid) ?? static::fail('The key is found.');
        static::assertSame(KeyStatus::Retiring, $retiring->status);
        static::assertEquals(Fixtures::now()->modify('+1 day'), $retiring->retiringAt);
        static::assertNull($retiring->retiredAt);

        $retiring->retire(Fixtures::now()->modify('+2 days'));
        $this->repository->save($retiring);

        $retired = $this->repository->find($tenant, $key->kid) ?? static::fail('The key is found.');
        static::assertSame(KeyStatus::Retired, $retired->status);
        static::assertEquals(Fixtures::now()->modify('+1 day'), $retired->retiringAt);
        static::assertEquals(Fixtures::now()->modify('+2 days'), $retired->retiredAt);
    }

    /**
     * SigningKeyRepositoryInterface::findPublished(): active and retiring keys, in creation order.
     */
    #[Test]
    public function theActiveKeyIsFoundAndThePublishedOnesComeInCreationOrder(): void
    {
        $tenant = Fixtures::tenant();
        $oldest = self::key($tenant, 'zzz-oldest', Fixtures::now()->modify('-2 days'));
        $oldest->startRetiring(Fixtures::now());
        $middle = self::key($tenant, 'aaa-middle', Fixtures::now()->modify('-1 day'));
        $middle->startRetiring(Fixtures::now());
        $middle->retire(Fixtures::now());
        $newest = self::key($tenant, 'mmm-newest', Fixtures::now());
        $this->repository->save($newest);
        $this->repository->save($oldest);
        $this->repository->save($middle);

        static::assertSame('mmm-newest', $this->repository->findActive($tenant, SignatureAlgorithm::RS256)?->kid);
        static::assertSame(['zzz-oldest', 'mmm-newest'], array_map(static fn (SigningKey $key): string => $key->kid, $this->repository->findPublished($tenant)));
    }

    #[Test]
    public function anEmptyOrMissingStorageHasNoKey(): void
    {
        $tenant = Fixtures::tenant();

        static::assertNull($this->repository->find($tenant, 'unknown'));
        static::assertNull($this->repository->findActive($tenant, SignatureAlgorithm::RS256));
        static::assertSame([], $this->repository->findPublished($tenant));
        static::assertDirectoryDoesNotExist($this->directory);
    }

    #[Test]
    public function keysAreScopedByTenant(): void
    {
        $acme = Fixtures::tenant();
        $other = Fixtures::tenant('other', 'https://id.other.example');
        $this->repository->save(self::key($other, Keys::pair()->kid));

        static::assertNull($this->repository->find($acme, Keys::pair()->kid));
        static::assertNull($this->repository->findActive($acme, SignatureAlgorithm::RS256));
        static::assertSame([], $this->repository->findPublished($acme));
        static::assertNotNull($this->repository->find($other, Keys::pair()->kid));
    }

    /**
     * A file under the slug of one tenant that names another is a storage fault, not a key of either.
     */
    #[Test]
    public function aFileOfAnotherTenantUnderTheSameSlugIsRefused(): void
    {
        $tenant = Fixtures::tenant();
        $impostor = Fixtures::tenant('acme', 'https://id.impostor.example');
        $this->repository->save(self::key($impostor, Keys::pair()->kid));

        $this->expectException(RuntimeException::class);
        $this->repository->find($tenant, Keys::pair()->kid);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function kidsThatCannotNameAFile(): iterable
    {
        yield 'a path' => ['../../etc/passwd'];
        yield 'a slash' => ['a/b'];
        yield 'a dot' => ['.'];
        yield 'empty' => [''];
        yield 'a space' => ['a b'];
    }

    #[Test]
    #[DataProvider('kidsThatCannotNameAFile')]
    public function aKidThatIsNotAThumbprintNamesNoFile(string $kid): void
    {
        static::assertNull($this->repository->find(Fixtures::tenant(), $kid));
    }

    #[Test]
    public function aKeyWhoseKidCannotNameAFileIsNotSaved(): void
    {
        $key = new SigningKey('../escape', Fixtures::tenant(), SignatureAlgorithm::RS256, [
            'kid' => '../escape',
        ] + Keys::pair()->publicJwk, 'sealed', Fixtures::now());

        $this->expectException(RuntimeException::class);
        $this->repository->save($key);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function corruptedDocuments(): iterable
    {
        yield 'not JSON' => ['{'];
        yield 'not an object' => ['[]'];
        yield 'no kid' => [json_encode([
            'algorithm' => 'RS256',
        ], JSON_THROW_ON_ERROR)];
        yield 'an unknown algorithm' => [json_encode(self::document([
            'algorithm' => 'HS256',
        ]), JSON_THROW_ON_ERROR)];
        yield 'an unknown status' => [json_encode(self::document([
            'status' => 'lost',
        ]), JSON_THROW_ON_ERROR)];
        yield 'a sealed key that is not base64' => [json_encode(self::document([
            'sealed_private_jwk' => '***',
        ]), JSON_THROW_ON_ERROR)];
        yield 'a public JWK that is not a map of strings' => [json_encode(self::document([
            'public_jwk' => [
                'kid' => 1,
            ],
        ]), JSON_THROW_ON_ERROR)];
        yield 'a public JWK missing its members' => [json_encode(self::document([
            'public_jwk' => [
                'kid' => 'x',
            ],
        ]), JSON_THROW_ON_ERROR)];
        yield 'a date that is not RFC 3339' => [json_encode(self::document([
            'created_at' => 'yesterday',
        ]), JSON_THROW_ON_ERROR)];
        yield 'a retiring key without its date' => [json_encode(self::document([
            'status' => 'retiring',
        ]), JSON_THROW_ON_ERROR)];
    }

    #[Test]
    #[DataProvider('corruptedDocuments')]
    public function aFileThatIsNotASigningKeyDocumentIsAFault(string $content): void
    {
        $tenant = Fixtures::tenant();
        mkdir($this->directory . '/acme', 0o700, true);
        file_put_contents($this->directory . '/acme/' . Keys::pair()->kid . '.json', $content);

        $this->expectException(RuntimeException::class);
        $this->repository->findPublished($tenant);
    }

    #[Test]
    public function theStorageIsPrivateToTheProcessOwnerAndLeavesNoTemporaryFile(): void
    {
        $tenant = Fixtures::tenant();
        $this->repository->save(self::key($tenant, Keys::pair()->kid));

        static::assertSame('700', decoct(fileperms($this->directory . '/acme') & 0o777));
        static::assertSame('600', decoct(fileperms($this->directory . '/acme/' . Keys::pair()->kid . '.json') & 0o777));
        static::assertSame([$this->directory . '/acme/' . Keys::pair()->kid . '.json'], glob($this->directory . '/acme/*'));
    }

    #[Test]
    public function aStorageThatCannotBeCreatedIsAFault(): void
    {
        file_put_contents($this->directory, 'a file where the directory should be');

        $this->expectException(RuntimeException::class);
        $this->repository->save(self::key(Fixtures::tenant(), Keys::pair()->kid));
    }

    /**
     * The document as written, with what the test wants wrong.
     *
     * @param array<string, mixed> $overrides
     *
     * @return array<string, mixed>
     */
    private static function document(array $overrides): array
    {
        return $overrides + [
            'kid' => Keys::pair()->kid,
            'tenant_id' => 'ignored: the tenant check comes after the shape check',
            'algorithm' => 'RS256',
            'public_jwk' => Keys::pair()->publicJwk,
            'sealed_private_jwk' => base64_encode('sealed'),
            'status' => 'active',
            'created_at' => '2026-09-15T10:00:00.000+00:00',
            'retiring_at' => null,
            'retired_at' => null,
        ];
    }

    private static function key(Tenant $tenant, string $kid, ?DateTimeImmutable $createdAt = null): SigningKey
    {
        return new SigningKey($kid, $tenant, SignatureAlgorithm::RS256, [
            'kid' => $kid,
        ] + Keys::pair()->publicJwk, 'sealed', $createdAt ?? Fixtures::now());
    }
}
