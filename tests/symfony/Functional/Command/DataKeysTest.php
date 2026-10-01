<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Command;

use Doctrine\DBAL\Connection;
use Heidi\Bundle\Doctrine\PersonalData\EncryptedColumnTypes;
use Heidi\Bundle\Doctrine\PersonalData\TenantDataKeyStores;
use Heidi\Bundle\Doctrine\PersonalData\TenantScopedEncrypter;
use Heidi\Bundle\Tests\Functional\Doctrine\PersonalData\RawRows;
use Heidi\Bundle\Tests\Functional\MessageHandler\RecordingEventHandler;
use Heidi\Core\Domain\Event\TenantDataKeysDestroyed;
use Heidi\Core\Domain\Event\TenantDataKeysRewrapped;
use Heidi\Core\Domain\Identity\EmailAddress;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Port\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
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
        $tester = self::console('heidi:data-keys:list');

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
        $tester = self::console('heidi:data-keys:list');

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
        $tester = self::console('heidi:data-keys:list');

        // Then
        static::assertStringNotContainsString($material, self::flattened($tester));
    }

    #[Test]
    public function theDestructionRefusesWithoutTheSlugTypedBack(): void
    {
        // Given
        self::sealSomething();

        // When
        $tester = self::console('heidi:data-keys:destroy');

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
        $tester = self::console('heidi:data-keys:destroy', [
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
        $sealed = self::connection()->fetchOne('SELECT username FROM heidi_user WHERE id = ?', [$user->id->toBinary()]);
        static::assertNotFalse($sealed);

        // When
        $tester = self::console('heidi:data-keys:destroy', [
            'slug' => self::tenant()->slug,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode());
        static::assertStringContainsString('erased', self::flattened($tester));
        static::assertSame([], self::rows());
        static::assertSame(
            $sealed,
            self::connection()->fetchOne('SELECT username FROM heidi_user WHERE id = ?', [$user->id->toBinary()]),
            'The destruction erased a key and not a row: what is gone is the means of reading it.',
        );
    }

    #[Test]
    public function theDestructionIsWrittenToTheAuditTrail(): void
    {
        // Given
        self::sealSomething();

        // When
        self::console('heidi:data-keys:destroy', [
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
        $tester = self::console('heidi:data-keys:rewrap');

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
        $tester = self::console('heidi:data-keys:rewrap', [
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
        $tester = self::console('heidi:data-keys:rewrap', [
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
        $tester = self::console('heidi:data-keys:rewrap', [
            '--to' => 'second',
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode());
        foreach (self::rows() as $row) {
            static::assertSame('second', $row['client']);
        }
        self::reload();
        $read = self::service('test.heidi.users', UserRepositoryInterface::class)->find($user->id);
        static::assertInstanceOf(User::class, $read);
        static::assertSame(self::USERNAME, $read->username);
    }

    #[Test]
    public function theRewrapIsWrittenToTheAuditTrail(): void
    {
        // Given
        self::sealSomething();

        // When
        self::console('heidi:data-keys:rewrap', [
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
     * A run from the client the keys have left lists nothing, which is what says the previous run moved
     * them all.
     */
    #[Test]
    public function aSecondDryRunFromTheOldClientListsNothing(): void
    {
        // Given
        self::sealSomething();
        self::console('heidi:data-keys:rewrap', [
            '--to' => 'second',
        ]);

        // When
        $tester = self::console('heidi:data-keys:rewrap', [
            '--to' => 'second',
            '--from' => 'test',
            '--dry-run' => true,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode());
        static::assertStringContainsString('holds no data key wrapped by "test"', self::flattened($tester));
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
        self::service('test.heidi.users', UserRepositoryInterface::class)->save($user);
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
