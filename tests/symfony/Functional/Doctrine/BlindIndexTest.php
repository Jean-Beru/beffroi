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
 * Decisions 0011 and 0018
 */
final class BlindIndexTest extends DatabaseTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        self::kms()->forget();
    }

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
     * Decision 0011
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
     * Decision 0018
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
     * Decision 0018
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
