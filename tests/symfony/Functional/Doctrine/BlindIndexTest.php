<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine;

use Doctrine\DBAL\Connection;
use Heidi\Bundle\Doctrine\PersonalData\BlindIndexedColumns;
use Heidi\Bundle\Doctrine\PersonalData\TenantBlindIndexes;
use Heidi\Bundle\Doctrine\PersonalData\TenantDataKeyStores;
use Heidi\Bundle\Doctrine\PersonalData\TenantScopedEncrypter;
use Heidi\Bundle\Tests\Functional\Doctrine\PersonalData\CountingKms;
use Heidi\Bundle\Tests\Fixture\AmbientTenant;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Exception\RuntimeException;
use Heidi\Core\Tests\Fixture\Fixtures;
use Psr\Container\ContainerInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DependencyInjection\ServiceLocator;
use Symfony\Component\KeyManagement\DataKeyGeneratorInterface;

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
     * One key per tenant, and one opening per projection: `BlindIndex` takes a wrapped key and unwraps it
     * itself, so the two projections of one tenant each open the one key of that tenant. Decision 0018
     * counts one opening per data key, and this is the one place where the count is per projection; what
     * would remove it is a `BlindIndex` that accepted an open handle, which is a change in the component
     * (heidi#418). The login journey touches one of the two, the lookup being by username.
     */
    #[Test]
    public function eachProjectionOpensTheOneIndexKeyOfTheTenantOnItsOwn(): void
    {
        // Given
        $indexes = self::indexesOf(self::tenant()->slug);

        // When
        $indexes->of(BlindIndexedColumns::of(User::class, 'username'))->of('ada-lovelace');
        $indexes->of(BlindIndexedColumns::of(User::class, 'email'))->of('ada@example.org');

        // Then
        static::assertCount(1, self::scopes());
        static::assertSame(1, self::kms()->minted);
        static::assertSame(2, self::kms()->unwrapped);
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
            self::clients(),
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
        $tag = self::service('test.heidi.blind_indexes', TenantBlindIndexes::class)->of(BlindIndexedColumns::of(User::class, 'username'))->of('ada-lovelace');

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
            self::clients(),
            self::store(),
            new AmbientTenant(Fixtures::tenant($slug)),
            TenantDataKeyStores::TABLE,
        );
    }

    /**
     * The one KMS client of this kernel, by the name the configuration gives it, which is the name every
     * row of the store carries.
     */
    private static function clients(): ContainerInterface
    {
        return new ServiceLocator([
            'test' => static fn (): DataKeyGeneratorInterface => self::service('test.heidi.kms', DataKeyGeneratorInterface::class),
        ]);
    }

    private static function store(): TenantDataKeyStores
    {
        return self::service('test.heidi.data_keys_index', TenantDataKeyStores::class);
    }

    /**
     * @return list<string>
     */
    private static function scopes(): array
    {
        $scopes = [];
        foreach (self::connection()->iterateAssociative('SELECT scope FROM heidi_data_key ORDER BY id') as $row) {
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
