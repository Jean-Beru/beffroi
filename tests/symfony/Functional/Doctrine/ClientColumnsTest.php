<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use Doctrine\DBAL\Connection;
use App\Doctrine\PersonalData\BlindIndexedColumns;
use App\Doctrine\PersonalData\TenantScopedEncrypter;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\RawRows;
use Beffroi\Core\Domain\PersonalData\Sealed;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\ClassifiedModel;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\SealedRows;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Oidc\Domain\Client\ClientRecord;
use Beffroi\Oidc\Domain\Client\ClientSecretInterface;
use Beffroi\Oidc\Domain\Client\HashedClientSecret;
use Beffroi\Oidc\Domain\Client\SharedClientSecret;
use Beffroi\Oidc\Port\ClientStoreInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function sort;
use function sprintf;

/**
 * Decisions 0011 and 0018
 */
final class ClientColumnsTest extends DatabaseTestCase
{
    private const string CONTACT = SealedRows::VALUES['beffroi_user']['email'];

    private const string CLIENT_NAME = SealedRows::VALUES['beffroi_client']['metadata'];

    private const string ASSIGNED_SCOPE = SealedRows::VALUES['beffroi_client']['assigned_metadata'];

    private const string ATTESTED_SOFTWARE = SealedRows::VALUES['beffroi_client']['attested_metadata'];

    private const string GRANTED_RESOURCE = SealedRows::VALUES['beffroi_client']['granted_metadata'];

    private const string SHARED_SECRET = SealedRows::VALUES['beffroi_client']['secret'];

    /**
     * @var list<string>
     */
    private const array SEALED = ['metadata', 'assigned_metadata', 'attested_metadata', 'granted_metadata', 'secret'];

    /**
     * Decision 0011
     */
    #[Test]
    public function theFixtureWritesEveryColumnTheClassificationDeclaresSealed(): void
    {
        // Given
        $sealed = [];
        foreach (ClassifiedModel::of(self::entityManager())->linesOf('beffroi_client') as $column => $line) {
            if ($line instanceof Sealed) {
                $sealed[] = $column;
            }
        }
        sort($sealed);

        // When
        $written = self::SEALED;
        sort($written);

        // Then
        static::assertSame($sealed, $written);
    }

    /**
     * RFC 7591 §2
     */
    #[Test]
    public function aClientIsReadBackWithWhatItRegisteredAndWhatWasAssignedToIt(): void
    {
        // Given
        self::record();
        self::reload();

        // When
        $found = self::clients()->findRecord(self::tenant(), 'the-engine');

        // Then
        static::assertInstanceOf(ClientRecord::class, $found);
        static::assertSame(self::CLIENT_NAME, $found->metadata['client_name'] ?? null);
        static::assertSame([self::CONTACT], $found->metadata['contacts'] ?? null);
        static::assertSame([self::ASSIGNED_SCOPE], $found->assigned['scope'] ?? null);
    }

    /**
     * RFC 7591 §3.1.1, RFC 7592 §2.2
     */
    #[Test]
    public function whatAStatementSignedOfAClientComesBackBesideWhatItRegistered(): void
    {
        // Given
        self::record(attested: true);
        self::reload();

        // When
        $found = self::clients()->findRecord(self::tenant(), 'the-engine');

        // Then
        static::assertInstanceOf(ClientRecord::class, $found);
        static::assertSame(
            [
                'software_id' => self::ATTESTED_SOFTWARE,
            ],
            $found->attested,
        );
    }

    #[Test]
    public function aClientNoStatementAttestedHoldsNothingInThatColumn(): void
    {
        // Given
        self::record();
        self::reload();

        // When
        $found = self::clients()->findRecord(self::tenant(), 'the-engine');

        // Then
        static::assertInstanceOf(ClientRecord::class, $found);
        static::assertNull($found->attested);
        static::assertNull(self::rows()[0]['attested_metadata']);
    }

    /**
     * Decision 0043
     */
    #[Test]
    public function whatAnInitialAccessTokenGaveAClientComesBackBesideWhatItRegistered(): void
    {
        // Given
        self::record(granted: true);
        self::reload();

        // When
        $found = self::clients()->findRecord(self::tenant(), 'the-engine');

        // Then
        static::assertInstanceOf(ClientRecord::class, $found);
        static::assertSame(
            [
                'resources' => [self::GRANTED_RESOURCE],
            ],
            $found->granted,
        );
    }

    #[Test]
    public function aClientNoTokenGaveAnythingHoldsNothingInThatColumn(): void
    {
        // Given
        self::record();
        self::reload();

        // When
        $found = self::clients()->findRecord(self::tenant(), 'the-engine');

        // Then
        static::assertInstanceOf(ClientRecord::class, $found);
        static::assertNull($found->granted);
        static::assertNull(self::rows()[0]['granted_metadata']);
    }

    /**
     * OIDC Core §9
     */
    #[Test]
    public function aSharedSecretComesBackAsTheValueItWas(): void
    {
        // Given
        self::record(new SharedClientSecret(self::SHARED_SECRET));
        self::reload();

        // When
        $found = self::clients()->findRecord(self::tenant(), 'the-engine');

        // Then
        static::assertInstanceOf(ClientRecord::class, $found);
        static::assertInstanceOf(SharedClientSecret::class, $found->secret);
        static::assertSame(self::SHARED_SECRET, $found->secret->value);
    }

    #[Test]
    public function aHashedSecretComesBackNamingItsAlgorithm(): void
    {
        // Given
        self::record(new HashedClientSecret(new PasswordHash(new Argon2id(), '$argon2id$the-digest')));
        self::reload();

        // When
        $found = self::clients()->findRecord(self::tenant(), 'the-engine');

        // Then
        static::assertInstanceOf(ClientRecord::class, $found);
        static::assertInstanceOf(HashedClientSecret::class, $found->secret);
        static::assertSame(Argon2id::NAME, $found->secret->hash->algorithm->name());
        static::assertSame('$argon2id$the-digest', $found->secret->hash->encoded);
    }

    #[Test]
    public function aClientWithNoSecretHoldsNothingInThatColumn(): void
    {
        // Given
        self::record();
        self::reload();

        // When
        $found = self::clients()->findRecord(self::tenant(), 'the-engine');

        // Then
        static::assertInstanceOf(ClientRecord::class, $found);
        static::assertNull($found->secret);
        static::assertNull(self::rows()[0]['secret']);
    }

    #[Test]
    #[DataProvider('provideSealedColumns')]
    public function theRowHoldsNoneOfThePlaintexts(string $column): void
    {
        // Given
        self::record(new SharedClientSecret(self::SHARED_SECRET), attested: true, granted: true);

        // When
        $stored = self::rows()[0][$column];

        // Then
        static::assertNotNull($stored, sprintf('beffroi_client.%s holds nothing, so there is nothing to search.', $column));
        foreach ([self::CONTACT, self::CLIENT_NAME, self::ASSIGNED_SCOPE, self::ATTESTED_SOFTWARE, self::GRANTED_RESOURCE, self::SHARED_SECRET] as $plaintext) {
            static::assertStringNotContainsString(
                $plaintext,
                (string) $stored,
                sprintf('beffroi_client.%s holds "%s" in the clear.', $column, $plaintext),
            );
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideSealedColumns(): iterable
    {
        foreach (self::SEALED as $column) {
            yield $column => [$column];
        }
    }

    /**
     * Decision 0018
     */
    #[Test]
    public function theRowOfAClientSealsUnderTheClientFamilyAndNotTheUserFamily(): void
    {
        // Given
        self::user();
        self::record();

        // When
        $scopes = self::connection()->fetchFirstColumn('SELECT scope FROM beffroi_data_key ORDER BY scope ASC');

        // Then
        $slug = self::tenant()->slug;
        static::assertSame(
            [
                TenantScopedEncrypter::scope($slug, BlindIndexedColumns::SCOPE),
                TenantScopedEncrypter::scope($slug, 'client'),
                TenantScopedEncrypter::scope($slug, 'user'),
            ],
            $scopes,
        );
    }

    private static function record(?ClientSecretInterface $secret = null, bool $attested = false, bool $granted = false): ClientRecord
    {
        return self::fixture()->client($secret, $attested, $granted);
    }

    private static function fixture(): SealedRows
    {
        return new SealedRows(self::getContainer(), self::tenant(), self::now());
    }

    /**
     * @return list<array<string, string|null>>
     */
    private static function rows(): array
    {
        $rows = RawRows::of(self::connection(), 'beffroi_client', self::SEALED);
        static::assertCount(1, $rows);

        return $rows;
    }

    private static function clients(): ClientStoreInterface
    {
        return self::service('test.beffroi.client_store', ClientStoreInterface::class);
    }

    private static function connection(): Connection
    {
        return self::entityManager()->getConnection();
    }
}
