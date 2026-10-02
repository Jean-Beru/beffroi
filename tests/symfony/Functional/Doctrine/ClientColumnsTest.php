<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Doctrine;

use Doctrine\DBAL\Connection;
use Beffroi\Bundle\Doctrine\PersonalData\BlindIndexedColumns;
use Beffroi\Bundle\Doctrine\PersonalData\TenantScopedEncrypter;
use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\RawRows;
use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\Sealed;
use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\SchemaColumns;
use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\SealedRows;
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
 * What a client registered of the people responsible for it, and the secret this provider handed it,
 * sealed and read back (decisions 0011 and 0018). The last family of columns this spike seals.
 *
 * **Three columns of one table and no index**: a client is found by `client_id`, unique under its tenant
 * and in the clear, and nothing looks a client up by a member of its metadata. That the registration
 * endpoint and the four responses of RFC 7592 are untouched is `ClientConfigurationTest`, and that both
 * methods that use a secret still authenticate from the column is `RegisteredClientFlowTest`; both run
 * against this mapping and neither is repeated here.
 *
 * **The secret is the one column of this schema that is neither a personal datum nor safe in the clear.**
 * A digest for a method that receives a secret would have needed nothing; the secret itself, which
 * `client_secret_jwt` signs with, cannot be hashed (OIDC Core §9). A credential that cannot be hashed is
 * sealed instead, which is what makes the first success criterion of this spike answerable for it: a dump
 * yields no usable client credential either.
 */
final class ClientColumnsTest extends DatabaseTestCase
{
    /**
     * Read from the shared fixture and declared nowhere else: the test that searches the whole database
     * searches for these very values, and two lists of the same values are two lists that disagree.
     */
    private const string CONTACT = SealedRows::VALUES['beffroi_user']['email'];

    private const string CLIENT_NAME = SealedRows::VALUES['beffroi_client']['metadata'];

    private const string ASSIGNED_SCOPE = SealedRows::VALUES['beffroi_client']['assigned_metadata'];

    private const string SHARED_SECRET = SealedRows::VALUES['beffroi_client']['secret'];

    /**
     * The columns of this table the classification of the schema declares sealed.
     *
     * @var list<string>
     */
    private const array SEALED = ['metadata', 'assigned_metadata', 'secret'];

    /**
     * The fixture writes every column the classification declares sealed on this table, and no other: a
     * column sealed without a value written here would be asserted against nothing, and the walk of the
     * schema is what says which those are (SchemaColumns, decision 0011).
     */
    #[Test]
    public function theFixtureWritesEveryColumnTheClassificationDeclaresSealed(): void
    {
        // Given
        $sealed = [];
        foreach (SchemaColumns::all()['beffroi_client'] as $column => $line) {
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
     * RFC 7591 §2: what the client registered comes back as it registered it, the `contacts` among it,
     * and what the policy of the tenant assigned comes back beside it and not among it.
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
     * OIDC Core §9: the secret a method signs with is the secret itself, and it comes back as the value it
     * was, which is the whole reason this column had to seal.
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

    /**
     * And the other shape, which names the algorithm it was made with and is read back as the class the
     * wiring holds for that name, exactly as the hash of a password is.
     */
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

    /**
     * A sealed column that accepts a null holds a null and not the envelope of an empty value: a client
     * the provider assigned no secret has none, and a secret read back as anything would be a secret.
     */
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

    /**
     * Column by column, which is the point of the data provider: a column that stopped sealing fails on
     * its own line. The shared secret is asserted here with the personal data, being what makes this table
     * the one the first success criterion of the spike could not have passed without.
     */
    #[Test]
    #[DataProvider('provideSealedColumns')]
    public function theRowHoldsNoneOfThePlaintexts(string $column): void
    {
        // Given
        self::record(new SharedClientSecret(self::SHARED_SECRET));

        // When
        $stored = self::rows()[0][$column];

        // Then
        static::assertNotNull($stored, sprintf('beffroi_client.%s holds nothing, so there is nothing to search.', $column));
        foreach ([self::CONTACT, self::CLIENT_NAME, self::ASSIGNED_SCOPE, self::SHARED_SECRET] as $plaintext) {
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
     * The scope of these three columns is the client family and not the user family, which is what makes
     * the promise of decision 0018 true of a client: the key that opens a client's row is not the key that
     * opens a user's, and destroying one reaches one.
     *
     * Writing a user mints two keys and not one, the family of its columns and the index key its tags are
     * derived under (decision 0011), so the three scopes are named here rather than two: what this says is
     * that a client's columns are a scope of their own, and that nothing writes them into the user's.
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

    private static function record(?ClientSecretInterface $secret = null): ClientRecord
    {
        return self::fixture()->client($secret);
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
