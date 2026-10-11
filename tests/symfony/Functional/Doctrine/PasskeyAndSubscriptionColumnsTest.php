<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Doctrine;

use function array_keys;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\RawRows;
use Beffroi\Core\Domain\PersonalData\Sealed;
use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\ClassifiedModel;
use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\SealedRows;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Domain\Identity\PushSubscription;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\PushSubscriptionRepositoryInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function sort;
use function sprintf;

/**
 * The name a person gave a passkey, and what a push subscription holds of one of their devices, sealed and
 * read back (decisions 0011 and 0018).
 *
 * Three columns over two tables, and **no index and no constraint moved**, which is what distinguishes
 * these two tables from `beffroi_user` and `beffroi_linked_identity`. Each has its own reason.
 *
 * A passkey is found by the credential ID its authenticator issued and, for a ceremony that starts without
 * a username, by the user handle: both are in the clear, being published by the authenticator and drawn at
 * random, and both keep the index they had. Nobody searches a passkey by the name its owner typed, so that
 * column needs no tag. That the lookup is untouched is `DoctrineCredentialRepositoryTest`, which runs
 * against this mapping and is not repeated here.
 *
 * And `beffroi_push_subscription` already holds the digest of its endpoint in a column of its own, with the
 * unique constraint and the lookup on it: that is the shape a blind index builds, built there for its own
 * reason, an endpoint being as long as its push service decided. The two tests at the end of this class are
 * the ones that had to be written, because they are what sealing the endpoint could have broken.
 */
final class PasskeyAndSubscriptionColumnsTest extends DatabaseTestCase
{
    /**
     * The personal data of a device, by the column each one lands in, over the two tables: what the fixture
     * writes and what the row must not hold.
     *
     * @var array<string, array<string, string>> table, then column, then the plaintext written there
     */
    /**
     * Read from the shared fixture and declared nowhere else, for the same reason as everywhere else: the
     * test that searches the whole database searches for these very values.
     *
     * @var array<string, array<string, string>>
     */
    private const array PLAINTEXTS = [
        'beffroi_passkey_credential' => SealedRows::VALUES['beffroi_passkey_credential'],
        'beffroi_push_subscription' => SealedRows::VALUES['beffroi_push_subscription'],
    ];

    /**
     * The fixture writes every column the classification of the schema declares sealed on these two tables,
     * and no other: a column sealed without a value written here would be asserted against nothing, and the
     * model is what says which those are (ClassifiedFieldsInterface, decision 0011).
     */
    #[Test]
    #[DataProvider('provideTables')]
    public function theFixtureWritesEveryColumnTheClassificationDeclaresSealed(string $table): void
    {
        // Given
        $sealed = [];
        foreach (ClassifiedModel::of(self::entityManager())->linesOf($table) as $column => $line) {
            if ($line instanceof Sealed) {
                $sealed[] = $column;
            }
        }
        sort($sealed);

        // When
        $written = array_keys(self::PLAINTEXTS[$table]);
        sort($written);

        // Then
        static::assertSame($sealed, $written);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideTables(): iterable
    {
        foreach (array_keys(self::PLAINTEXTS) as $table) {
            yield $table => [$table];
        }
    }

    /**
     * The domain does not change because the column seals: the name comes back as the person typed it, the
     * encrypted type decorating the type the column had.
     */
    #[Test]
    public function aPasskeyIsReadBackWithTheNameItsOwnerGaveIt(): void
    {
        // Given
        $saved = self::passkey(self::user());
        self::reload();

        // When
        $read = self::credentials()->find($saved->id);

        // Then
        static::assertInstanceOf(PasskeyCredential::class, $read);
        static::assertSame(self::PLAINTEXTS['beffroi_passkey_credential']['name'], $read->name);
    }

    #[Test]
    public function aSubscriptionIsReadBackWithItsEndpointAndItsLabel(): void
    {
        // Given
        $saved = self::subscription(self::user());
        self::reload();

        // When
        $read = self::subscriptions()->find($saved->id);

        // Then
        static::assertInstanceOf(PushSubscription::class, $read);
        static::assertSame(self::PLAINTEXTS['beffroi_push_subscription']['endpoint'], $read->endpoint);
        static::assertSame(self::PLAINTEXTS['beffroi_push_subscription']['label'], $read->label);
    }

    /**
     * A sealed column that accepts a null holds a null and not the envelope of an empty string, which is
     * the one thing an encrypted type has to get right on a nullable column: a browser nobody named has no
     * label, and a label read back as an empty string would be a label.
     */
    #[Test]
    public function aBrowserNobodyNamedIsReadBackWithNoLabel(): void
    {
        // Given
        $saved = self::subscription(self::user(), label: null);
        self::reload();

        // When
        $read = self::subscriptions()->find($saved->id);

        // Then
        static::assertInstanceOf(PushSubscription::class, $read);
        static::assertNull($read->label);
        static::assertNull(self::rows('beffroi_push_subscription')[0]['label']);
    }

    /**
     * Column by column over the two tables, which is the point of the data provider: a column that stopped
     * sealing fails on its own line.
     */
    #[Test]
    #[DataProvider('provideSealedColumns')]
    public function theRowHoldsNoneOfThePlaintexts(string $table, string $column, string $plaintext): void
    {
        // Given
        self::rowsOfBothTables();

        // When
        $stored = self::rows($table)[0][$column];

        // Then
        static::assertNotNull($stored, sprintf('%s.%s holds nothing, so there is nothing to search.', $table, $column));
        static::assertStringNotContainsString(
            $plaintext,
            (string) $stored,
            sprintf('%s.%s holds "%s" in the clear.', $table, $column, $plaintext),
        );
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function provideSealedColumns(): iterable
    {
        foreach (self::PLAINTEXTS as $table => $columns) {
            foreach ($columns as $column => $plaintext) {
                yield $table . '.' . $column => [$table, $column, $plaintext];
            }
        }
    }

    /**
     * Push API §4: the same browser subscribing again hands back the endpoint it already had, and that is
     * what says it is this browser. The lookup matches on the digest, which the domain computes from the
     * endpoint it is given and which stays in the clear, so sealing the endpoint takes nothing from it.
     */
    #[Test]
    public function aBrowserIsStillRecognisedByTheDigestOfItsSealedEndpoint(): void
    {
        // Given
        $user = self::user();
        $saved = self::subscription($user);
        self::reload();

        // When
        $found = self::subscriptions()
            ->findByEndpoint(
                self::users()->find($saved->user->id) ?? static::fail('The user was not stored.'),
                self::PLAINTEXTS['beffroi_push_subscription']['endpoint'],
            );

        // Then
        static::assertInstanceOf(PushSubscription::class, $found);
        static::assertTrue($found->id->equals($saved->id));
    }

    /**
     * And the constraint that holds it, which is on the digest and not on the sealed column: two rows for
     * one browser would be two notifications for one request.
     */
    #[Test]
    public function aSecondSubscriptionForTheSameBrowserIsRefusedByTheConstraintThatIsThere(): void
    {
        // Given
        $user = self::user();
        self::subscription($user);

        // Then
        $this->expectException(UniqueConstraintViolationException::class);

        // When
        self::subscription($user, label: 'The same browser, said twice');
    }

    /**
     * One row of each of the two tables, written through the repositories a request writes them with.
     */
    private static function rowsOfBothTables(): void
    {
        $user = self::user();
        self::passkey($user);
        self::subscription($user);
    }

    private static function passkey(User $user): PasskeyCredential
    {
        return self::fixture()->passkey($user);
    }

    private static function subscription(User $user, ?string $label = self::PLAINTEXTS['beffroi_push_subscription']['label']): PushSubscription
    {
        return self::fixture()->subscription($user, $label);
    }

    private static function fixture(): SealedRows
    {
        return new SealedRows(self::getContainer(), self::tenant(), self::now());
    }

    /**
     * @return list<array<string, string|null>>
     */
    private static function rows(string $table): array
    {
        $rows = RawRows::of(self::connection(), $table, array_keys(self::PLAINTEXTS[$table]));
        static::assertCount(1, $rows);

        return $rows;
    }

    private static function users(): UserRepositoryInterface
    {
        return self::service('test.beffroi.users', UserRepositoryInterface::class);
    }

    private static function credentials(): CredentialRepositoryInterface
    {
        return self::service('test.beffroi.credentials', CredentialRepositoryInterface::class);
    }

    private static function subscriptions(): PushSubscriptionRepositoryInterface
    {
        return self::service('test.beffroi.push_subscriptions', PushSubscriptionRepositoryInterface::class);
    }

    private static function connection(): Connection
    {
        return self::entityManager()->getConnection();
    }
}
