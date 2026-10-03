<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Command;

use Doctrine\DBAL\Connection;
use Beffroi\Bundle\Doctrine\PersonalData\EncryptedColumnTypes;
use Beffroi\Bundle\Doctrine\PersonalData\TenantDataKeyStores;
use Beffroi\Bundle\Doctrine\PersonalData\TenantScopedEncrypter;
use Beffroi\Bundle\Doctrine\PersonalData\TenantDataKeyDestruction;
use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\RawRows;
use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\SchemaColumns;
use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\Sealed;
use Beffroi\Bundle\Tests\Functional\MessageHandler\RecordingEventHandler;
use Beffroi\Core\Domain\Event\TenantDataKeysDestroyed;
use Beffroi\Core\Domain\Event\TenantDataKeysRewrapped;
use Beffroi\Core\Domain\Identity\Address;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Issuer;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use function array_column;
use function array_filter;
use function count;
use function sprintf;
use Throwable;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Uid\Uuid;

/**
 * What an operator holds the data keys of a tenant with (decision 0018): one command that reads them, one
 * that moves them to another KMS, and one that erases them, which is the only thing that erases a data
 * key.
 *
 * The tenant is the one this kernel is configured for, there being one. What a second tenant does not see
 * of the first is what the scope says, the slug being its prefix, and the unit test of the encrypter is
 * what plays two of them.
 */
final class DataKeysTest extends ConsoleTestCase
{
    private const string USERNAME = 'ada-of-the-keys';

    #[Test]
    public function theListingShowsTheScopesOfTheTenantAndTheClientThatOpensEach(): void
    {
        // Given
        self::sealSomething();

        // When
        $tester = self::console('beffroi:data-keys:list');

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode());
        $display = self::flattened($tester);
        static::assertStringContainsString(TenantScopedEncrypter::scope(self::tenant()->slug, 'user'), $display);
        static::assertStringContainsString('current', $display);
        static::assertStringContainsString('test', $display);
    }

    /**
     * A data key is minted at the first write of its family, so a tenant that has sealed nothing holds
     * none, which is not an error: what it is told is which families there are to hold one for.
     */
    #[Test]
    public function aTenantThatHasSealedNothingIsToldWhichFamiliesThereAre(): void
    {
        // When
        $tester = self::console('beffroi:data-keys:list');

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode());
        $display = self::flattened($tester);
        static::assertStringContainsString('holds no data key', $display);
        foreach (EncryptedColumnTypes::families() as $family) {
            static::assertStringContainsString($family, $display);
        }
    }

    /**
     * The listing never opens a key, and it never shows its material: what the store holds is wrapped, and
     * a reading of this kind has no business unwrapping it.
     */
    #[Test]
    public function theListingShowsNoKeyMaterial(): void
    {
        // Given
        self::sealSomething();
        $material = RawRows::of(self::connection(), TenantDataKeyStores::TABLE, ['key_material'])[0]['key_material'] ?? null;
        static::assertNotNull($material);

        // When
        $tester = self::console('beffroi:data-keys:list');

        // Then
        static::assertStringNotContainsString($material, self::flattened($tester));
    }

    #[Test]
    public function theDestructionRefusesWithoutTheSlugTypedBack(): void
    {
        // Given
        self::sealSomething();

        // When
        $tester = self::console('beffroi:data-keys:destroy');

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertStringContainsString('Type the slug of the tenant back', self::flattened($tester));
        static::assertNotSame([], self::rows());
    }

    #[Test]
    public function theDestructionRefusesAnotherSlug(): void
    {
        // Given
        self::sealSomething();

        // When
        $tester = self::console('beffroi:data-keys:destroy', [
            'slug' => 'another-tenant',
        ]);

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertStringContainsString('is not the slug of the tenant', self::flattened($tester));
        static::assertNotSame([], self::rows());
    }

    /**
     * The fifth success criterion of the spike, as far as a test of one kernel reaches: after the
     * destruction the rows are still there and nothing opens them. That it reaches one tenant and not
     * another is played against the stack (#410).
     */
    #[Test]
    public function theDestructionErasesTheKeysAndLeavesTheRowsUnreadable(): void
    {
        // Given
        $user = self::sealSomething();
        $sealed = self::connection()->fetchOne('SELECT username FROM beffroi_user WHERE id = ?', [$user->id->toBinary()]);
        static::assertNotFalse($sealed);

        // When
        $tester = self::console('beffroi:data-keys:destroy', [
            'slug' => self::tenant()->slug,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode());
        static::assertStringContainsString('erased', self::flattened($tester));
        // the destruction is itself an act, and the provenance of an act is sealed (issue #454), so the
        // journal of this erasure mints one key of its own; what it does not do is bring a sealed value
        // back, which the read below is the proof of
        static::assertSame(
            [
                [
                    'scope' => self::tenant()->slug . '.journal',
                    'client' => 'test',
                ],
            ],
            self::rows(),
        );
        static::assertSame(
            $sealed,
            self::connection()->fetchOne('SELECT username FROM beffroi_user WHERE id = ?', [$user->id->toBinary()]),
            'The destruction erased a key and not a row: what is gone is the means of reading it.',
        );
    }

    #[Test]
    public function theDestructionIsWrittenToTheAuditTrail(): void
    {
        // Given
        self::sealSomething();

        // When
        self::console('beffroi:data-keys:destroy', [
            'slug' => self::tenant()->slug,
        ]);

        // Then
        $event = self::recorded(TenantDataKeysDestroyed::class);
        static::assertInstanceOf(TenantDataKeysDestroyed::class, $event);
        static::assertTrue($event->tenant->equals(self::tenant()));
        static::assertGreaterThan(0, $event->keys);
        static::assertGreaterThan(0, $event->scopes);
    }

    #[Test]
    public function theRewrapNeedsTheClientItMovesTo(): void
    {
        // Given
        self::sealSomething();

        // When
        $tester = self::console('beffroi:data-keys:rewrap');

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertStringContainsString('--to', self::flattened($tester));
    }

    /**
     * A tenant that holds nothing is told so rather than handed a run that moves nothing: the command of
     * the component would answer "0 data key(s) would move", which says less.
     */
    #[Test]
    public function theRewrapOfATenantThatHoldsNothingSaysSo(): void
    {
        // When
        $tester = self::console('beffroi:data-keys:rewrap', [
            '--to' => 'second',
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode());
        static::assertStringContainsString('holds no data key', self::flattened($tester));
    }

    #[Test]
    public function aDryRunListsWhatWouldMoveAndWritesNothing(): void
    {
        // Given
        self::sealSomething();
        $before = self::rows();

        // When
        $tester = self::console('beffroi:data-keys:rewrap', [
            '--to' => 'second',
            '--dry-run' => true,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode());
        static::assertStringContainsString('would move', self::flattened($tester));
        static::assertSame($before, self::rows());
        static::assertNull(self::recorded(TenantDataKeysRewrapped::class));
    }

    /**
     * The keys of the tenant wrapped by the other client, and every sealed value read back afterwards: a
     * rewrap changes how a key is protected and not the key, so nothing of what it sealed is rewritten.
     */
    #[Test]
    public function theRewrapMovesTheKeysAndWhatTheySealedStillReads(): void
    {
        // Given
        $user = self::sealSomething();

        // When
        $tester = self::console('beffroi:data-keys:rewrap', [
            '--to' => 'second',
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode());
        foreach (self::rows() as $row) {
            // the rewrap is itself an act, and the provenance of an act is sealed (issue #454), so the
            // journal of this run mints one key under the client the configuration names, after the run
            // moved what there was: everything is on the other client except the scope of the journal
            static::assertSame($row['scope'] === self::tenant()->slug . '.journal' ? 'test' : 'second', $row['client']);
        }
        self::reload();
        $read = self::service('test.beffroi.users', UserRepositoryInterface::class)->find($user->id);
        static::assertInstanceOf(User::class, $read);
        static::assertSame(self::USERNAME, $read->username);
    }

    #[Test]
    public function theRewrapIsWrittenToTheAuditTrail(): void
    {
        // Given
        self::sealSomething();

        // When
        self::console('beffroi:data-keys:rewrap', [
            '--to' => 'second',
        ]);

        // Then
        $event = self::recorded(TenantDataKeysRewrapped::class);
        static::assertInstanceOf(TenantDataKeysRewrapped::class, $event);
        static::assertSame('second', $event->to);
        static::assertNull($event->from);
        static::assertGreaterThan(0, $event->keys);
    }

    /**
     * A run from the client the keys have left lists what has been written since and nothing more, which
     * is what says the previous run moved them all. What has been written since is one key: the journal of
     * that run itself, whose provenance is sealed under the client the configuration names (issue #454).
     */
    #[Test]
    public function aSecondDryRunFromTheOldClientListsOnlyWhatWasWrittenSince(): void
    {
        // Given
        self::sealSomething();
        self::console('beffroi:data-keys:rewrap', [
            '--to' => 'second',
        ]);

        // When
        $tester = self::console('beffroi:data-keys:rewrap', [
            '--to' => 'second',
            '--from' => 'test',
            '--dry-run' => true,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode());
        static::assertStringContainsString('1 data key(s) would move', self::flattened($tester));
        static::assertSame([self::tenant()->slug . '.journal'], array_column(array_filter(
            self::rows(),
            static fn (array $row): bool => $row['client'] === 'test',
        ), 'scope'));
    }

    /**
     * The promise the bridge makes, and the one "it still reads" does not prove: a rewrap changes how a
     * data key is wrapped and never the key, so every sealed column keeps the exact bytes it had. A rewrap
     * that had rewritten a payload would have had to read one, which is the round trip a store exists to
     * spare.
     *
     * Compared column by column, over the columns the classification declares sealed rather than over a
     * list of its own, so a column sealed later is compared without this test being touched.
     */
    #[Test]
    public function everySealedColumnIsByteIdenticalBeforeAndAfterTheRewrap(): void
    {
        // Given
        self::sealSomething();
        $before = self::sealedColumns();

        // When
        $tester = self::console('beffroi:data-keys:rewrap', [
            '--to' => 'second',
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode());
        static::assertGreaterThanOrEqual(4, count($before), 'a comparison of nothing would pass for nothing.');
        static::assertSame($before, self::sealedColumns(), 'a rewrap that moved a payload would be a rewrap that read one.');
    }

    /**
     * The fourth success criterion of the spike: destroying the data keys of a tenant makes what they
     * sealed unreadable. The row stays untouched, what is gone is the means of opening it, so the read is
     * refused rather than answered with something.
     *
     * The tenant here is the configured one, which is the only one a unit of work can read through: an
     * encrypter composes its scope from the ambient tenant, so a row of another tenant read while this one
     * is ambient is not a row this provider ever tries to open. What reaches one tenant and not the other
     * is the test below.
     */
    #[Test]
    public function aRowWhoseDataKeyWasDestroyedNoLongerOpens(): void
    {
        // Given
        $user = self::sealSomething();
        self::console('beffroi:data-keys:destroy', [
            'slug' => self::tenant()->slug,
        ]);
        self::reload();

        // When
        $thrown = null;
        try {
            self::service('test.beffroi.users', UserRepositoryInterface::class)->find($user->id);
        } catch (Throwable $caught) {
            $thrown = $caught;
        }

        // Then
        static::assertNotNull($thrown, 'a row whose data key is gone read back as something, which is worse than refusing.');
        static::assertStringContainsString(
            'Data key',
            self::reasonOf($thrown),
            'the refusal names the data key the row refers to, which is what an operator needs to know.',
        );
        static::assertStringContainsString('was not found in the store', self::reasonOf($thrown));
    }

    /**
     * And nothing else: a destruction that took both tenants down is the failure this criterion exists to
     * catch, so the tenant that was left alone is read in a test of its own.
     */
    #[Test]
    public function aRowOfTheOtherTenantStillOpens(): void
    {
        // Given
        $mine = self::sealSomething();
        $other = self::anotherTenant();
        self::sealSomethingFor($other, 'bob-of-the-other-tenant');

        // When
        self::destroyTheKeysOf($other);

        // Then
        $read = self::service('test.beffroi.users', UserRepositoryInterface::class)->find($mine->id);
        static::assertInstanceOf(User::class, $read);
        static::assertSame(self::USERNAME, $read->username);
    }

    /**
     * What every sealed column of the user table holds, as the database holds it.
     *
     * A column the fixture left empty is left out, a null having no bytes to compare, and the count of what
     * is compared is asserted where the comparison is.
     *
     * @return array<string, string>
     */
    private static function sealedColumns(): array
    {
        $columns = [];
        foreach (SchemaColumns::all()['beffroi_user'] as $column => $line) {
            if ($line instanceof Sealed) {
                $columns[] = $column;
            }
        }

        $rows = RawRows::of(self::connection(), 'beffroi_user', $columns);
        static::assertCount(1, $rows);

        $held = [];
        foreach ($rows[0] as $column => $value) {
            if ($value !== null) {
                $held[$column] = $value;
            }
        }

        return $held;
    }

    private static function anotherTenant(): Tenant
    {
        $other = new Tenant(Uuid::v7(), 'other', new Issuer('https://other.test'), 'Other', self::now());
        self::entityManager()->persist($other);
        self::entityManager()->flush();

        return $other;
    }

    private static function destroyTheKeysOf(Tenant $tenant): void
    {
        self::service(TenantDataKeyDestruction::class, TenantDataKeyDestruction::class)->destroy($tenant, 'the test');
        self::reload();
    }

    /**
     * The message of a failure and of whatever it was wrapped in, a Doctrine type reporting the conversion
     * and carrying the cause under it.
     */
    private static function reasonOf(Throwable $thrown): string
    {
        $reason = $thrown->getMessage();
        $cause = $thrown->getPrevious();
        while ($cause !== null) {
            $reason .= ' ' . $cause->getMessage();
            $cause = $cause->getPrevious();
        }

        return $reason;
    }

    /**
     * A user of another tenant with the same sealed columns written, so that what is compared between the
     * two tenants is the same thing.
     */
    private static function sealSomethingFor(Tenant $tenant, string $username): User
    {
        $user = User::create(
            Uuid::v7(),
            $tenant,
            new Subject($username . '-subject'),
            $username,
            self::now(),
            new EmailAddress('bob@example.org'),
        );
        $user->changePhoneNumber('+441632960542', false, self::now());
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($user);
        self::reload();

        return $user;
    }

    /**
     * A user with a sealed column written, which is what mints the data key of its family and the index
     * key of the tenant.
     */
    private static function sealSomething(): User
    {
        $user = User::create(
            Uuid::v7(),
            self::tenant(),
            new Subject('ada-of-the-keys-subject'),
            self::USERNAME,
            self::now(),
            new EmailAddress('ada@example.org'),
        );
        $user->changePhoneNumber('+441632960541', false, self::now());
        $user->changeAddress(new Address('12 Grand Rue, Saint-Germain'), self::now());
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($user);
        self::reload();

        return $user;
    }

    /**
     * @return list<array<string, mixed>>
     */
    private static function rows(): array
    {
        return self::connection()
            ->fetchAllAssociative(
                sprintf('SELECT scope, client FROM %s ORDER BY scope ASC', TenantDataKeyStores::TABLE),
            );
    }

    /**
     * @param class-string $class
     */
    private static function recorded(string $class): ?object
    {
        foreach (self::service(RecordingEventHandler::class, RecordingEventHandler::class)->events as $event) {
            if ($event instanceof $class) {
                return $event;
            }
        }

        return null;
    }

    private static function connection(): Connection
    {
        return self::entityManager()->getConnection();
    }
}
