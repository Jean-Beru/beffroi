<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use function array_keys;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\RawRows;
use Beffroi\Core\Domain\PersonalData\Sealed;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\ClassifiedModel;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\SealedRows;
use Beffroi\Core\Domain\Credential\Attestation\ModelProof;
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

final class PasskeyAndSubscriptionColumnsTest extends DatabaseTestCase
{
    /**
     * @var array<string, array<string, string>> table, then column, then the plaintext written there
     */
    private const array PLAINTEXTS = [
        'beffroi_passkey_credential' => SealedRows::VALUES['beffroi_passkey_credential'],
        'beffroi_push_subscription' => SealedRows::VALUES['beffroi_push_subscription'],
    ];

    /**
     * Decision 0011
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

    /**
     * WebAuthn Level 3 §8.2.2, Decision 0046
     */
    #[Test]
    public function aPasskeyIsReadBackWithTheSerialNumberOfItsAuthenticator(): void
    {
        // Given
        $saved = self::passkey(self::user());
        self::reload();

        // When
        $read = self::credentials()->find($saved->id);

        // Then
        static::assertInstanceOf(PasskeyCredential::class, $read);
        static::assertSame(self::PLAINTEXTS['beffroi_passkey_credential']['serial_number'], $read->serialNumber);
        static::assertSame(ModelProof::Enterprise, $read->modelProof);
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
     * Push API §3.4
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
