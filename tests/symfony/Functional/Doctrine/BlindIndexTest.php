<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use Doctrine\DBAL\Connection;
use App\Doctrine\PersonalData\BlindIndexedColumns;
use App\Doctrine\PersonalData\TenantBlindIndexes;
use App\Doctrine\PersonalData\TenantDataKeyStores;
use App\Doctrine\PersonalData\TenantScopedEncrypter;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\CountingKms;
use App\Tests\Symfony\Fixture\AmbientTenant;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;

/**
 * The index key of a tenant, where it lives and what it costs (decisions 0011 and 0018).
 *
 * The key is a row of the data key table in a scope of its own, on a store whose keys never retire, so
 * that `key-management:rewrap-data-keys` carries it along when a deployment changes master key or backend
 * and no second command has to be remembered. It is never rotated: every tag already written was derived
 * under it.
 *
 * A second tenant is stood up here rather than configured, there being one tenant in the configuration of
 * a deployment and of this kernel: what changes between the two is the ambient tenant and nothing else,
 * which is what decision 0018 says decides a scope.
 */
final class BlindIndexTest extends DatabaseTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        self::kms()->forget();
    }

    /**
     * The scope carries the slug and is no family of columns, so the index key shares no store with the
     * keys that retire after thirty days.
     */
    #[Test]
    public function theIndexKeyIsARowOfTheStoreInAScopeOfItsOwn(): void
    {
        // When
        self::tagOf(self::tenant()->slug, 'ada-lovelace');

        // Then
        static::assertSame(
            [TenantScopedEncrypter::scope(self::tenant()->slug, BlindIndexedColumns::SCOPE)],
            self::scopes(),
        );
    }

    /**
     * Decision 0011 refuses an index key shared between two tenants: the same username of two tenants is
     * two tags, so the column says nothing about who else holds that username elsewhere.
     */
    #[Test]
    public function twoTenantsDeriveDifferentTagsForOneUsername(): void
    {
        // When
        $ofAcme = self::tagOf('acme', 'ada-lovelace');
        $ofGlobex = self::tagOf('globex', 'ada-lovelace');

        // Then
        static::assertNotSame($ofAcme, $ofGlobex);
    }

    /**
     * Decision 0018 counts one opening per data key and per thread. The index key is unwrapped at the first
     * tag and held, so a page that looks a user up on a thread that already did pays nothing.
     */
    #[Test]
    public function theIndexKeyIsOpenedOnceWhateverTheNumberOfTagsDerived(): void
    {
        // Given
        $indexes = self::indexesOf(self::tenant()->slug);
        $column = BlindIndexedColumns::of(User::class, 'username');

        // When
        for ($i = 0; $i < 20; ++$i) {
            $indexes->of($column)->of('ada-' . $i);
        }

        // Then
        static::assertSame(1, self::kms()->minted);
        static::assertSame(1, self::kms()->unwrapped);
    }

    /**
     * One key per tenant and one opening for every index over it: the store opens the row once and
     * `StoredKeyBlindIndex` derives under the handle it holds, so the two columns of one tenant cost the
     * opening of one and not of each. Decision 0018 counts one opening per data key and per thread, and
     * this is where the count is read.
     */
    #[Test]
    public function thePairOfColumnsOfOneTenantCostsOneOpeningOfItsIndexKey(): void
    {
        // Given
        $indexes = self::indexesOf(self::tenant()->slug);

        // When
        $indexes->of(BlindIndexedColumns::of(User::class, 'username'))->of('ada-lovelace');
        $indexes->of(BlindIndexedColumns::of(User::class, 'email'))->of('ada@example.org');

        // Then
        static::assertCount(1, self::scopes());
        static::assertSame(1, self::kms()->minted);
        static::assertSame(1, self::kms()->unwrapped);
    }

    /**
     * The key of an index scope is its first row and not its newest, which is the one place this reads the
     * table differently from the store of the bridge: a rotation nobody asked for would otherwise leave
     * every tag already written unreachable.
     */
    #[Test]
    public function aSecondRowInTheScopeIsNotWhatTheTagsAreDerivedUnder(): void
    {
        // Given
        $before = self::tagOf(self::tenant()->slug, 'ada-lovelace');

        // When
        self::store()->rotate(TenantScopedEncrypter::scope(self::tenant()->slug, BlindIndexedColumns::SCOPE));

        // Then
        static::assertCount(2, self::scopes());
        static::assertSame($before, self::tagOf(self::tenant()->slug, 'ada-lovelace'));
    }

    /**
     * A tag derived under the index key of another tenant is a tag no search of either tenant matches, so
     * a unit of work with no ambient tenant is refused rather than answered.
     */
    #[Test]
    public function aTagWithNoAmbientTenantIsRefused(): void
    {
        // Given
        $indexes = new TenantBlindIndexes(
            self::connection(),
            self::store(),
            new AmbientTenant(null),
            TenantDataKeyStores::TABLE,
        );

        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageIs('No tenant is ambient, so the blind index of "usernameIndex" cannot be derived: a tag derived under the index key of another tenant is a tag no search of either tenant matches.');

        // When
        $indexes->of(BlindIndexedColumns::of(User::class, 'username'));
    }

    /**
     * The one the container wires, which is what the repository is handed: the tenant it indexes for is
     * the one the configuration names, through the same provider every use case receives.
     */
    #[Test]
    public function theIndexesOfTheContainerDeriveForTheConfiguredTenant(): void
    {
        // When
        $tag = self::service('test.beffroi.blind_indexes', TenantBlindIndexes::class)->of(BlindIndexedColumns::of(User::class, 'username'))->of('ada-lovelace');

        // Then
        static::assertSame(self::tagOf(self::tenant()->slug, 'ada-lovelace'), $tag);
    }

    private static function tagOf(string $slug, string $username): string
    {
        return self::indexesOf($slug)->of(BlindIndexedColumns::of(User::class, 'username'))->of($username);
    }

    /**
     * The indexes of a tenant the test decides, over the store and the connection of the container: what
     * is replaced is the ambient tenant and nothing else.
     */
    private static function indexesOf(string $slug): TenantBlindIndexes
    {
        return new TenantBlindIndexes(
            self::connection(),
            self::store(),
            new AmbientTenant(Fixtures::tenant($slug)),
            TenantDataKeyStores::TABLE,
        );
    }

    private static function store(): TenantDataKeyStores
    {
        return self::service('test.beffroi.data_keys_index', TenantDataKeyStores::class);
    }

    /**
     * @return list<string>
     */
    private static function scopes(): array
    {
        $scopes = [];
        foreach (self::connection()->iterateAssociative('SELECT scope FROM beffroi_data_key ORDER BY id') as $row) {
            static::assertIsString($row['scope']);
            $scopes[] = $row['scope'];
        }

        return $scopes;
    }

    private static function kms(): CountingKms
    {
        return self::service(CountingKms::class, CountingKms::class);
    }

    private static function connection(): Connection
    {
        return self::entityManager()->getConnection();
    }
}
