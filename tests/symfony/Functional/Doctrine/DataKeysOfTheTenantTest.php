<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use App\Doctrine\PersonalData\DataKeysOfTheTenant;
use App\Doctrine\PersonalData\TenantDataKeyStores;
use App\Doctrine\PersonalData\TenantScopedEncrypter;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\CountingKms;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Port\UserRepositoryInterface;
use Doctrine\DBAL\ParameterType;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use function str_repeat;

/**
 * Decision 0018
 */
final class DataKeysOfTheTenantTest extends DatabaseTestCase
{
    private const string FAMILY = 'user';

    #[Test]
    public function everyDataKeyOfTheTenantIsOpenedRetiredOnesIncluded(): void
    {
        // Given
        $this->twoPeopleUnderTwoKeysOfTheirFamily();
        $this->aProcessThatOpenedNothing();

        // When
        self::opening()->open(self::tenant());

        // Then
        static::assertSame(3, self::kms()->unwrapped);
        static::assertSame(0, self::kms()->minted);
    }

    #[Test]
    public function aPersonIsFoundAndReadUnderKeysOpenedAhead(): void
    {
        // Given
        $this->twoPeopleUnderTwoKeysOfTheirFamily();
        $this->aProcessThatOpenedNothing();
        self::opening()->open(self::tenant());
        self::kms()->forget();

        // When
        $alice = self::users()->findByUsername(self::tenant(), 'alice');
        $bob = self::users()->findByUsername(self::tenant(), 'bob');

        // Then
        static::assertSame(['alice', 'bob'], [$alice?->username, $bob?->username]);
        static::assertSame(0, self::kms()->unwrapped);
    }

    #[Test]
    public function aTenantThatSealedNothingIsMintedNoKey(): void
    {
        // Given
        $this->aProcessThatOpenedNothing();

        // When
        self::opening()->open(self::tenant());

        // Then
        static::assertSame(0, self::kms()->minted);
        static::assertSame(0, self::rowsOfTheTenant());
    }

    #[Test]
    public function aDataKeyTheStoreRefusesIsARefusalOfTheTenant(): void
    {
        // Given
        self::user('alice', 'alice-subject');
        self::entityManager()
            ->getConnection()
            ->executeStatement(
                'UPDATE ' . TenantDataKeyStores::TABLE . ' SET binding = ? WHERE scope = ?',
                [str_repeat("\0", 32), TenantScopedEncrypter::scope(self::tenant()->slug, self::FAMILY)],
                [ParameterType::BINARY, ParameterType::STRING],
            );
        $this->aProcessThatOpenedNothing();

        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageIs(sprintf('A data key of the tenant "%s" could not be opened.', self::tenant()->slug));

        // When
        self::opening()->open(self::tenant());
    }

    #[Test]
    public function theKeysOfAnotherTenantAreLeftUnopened(): void
    {
        // Given
        self::stores()->current(TenantScopedEncrypter::scope('globex', self::FAMILY));
        $this->aProcessThatOpenedNothing();

        // When
        self::opening()->open(self::tenant());

        // Then
        static::assertSame(0, self::kms()->unwrapped);
    }

    private function twoPeopleUnderTwoKeysOfTheirFamily(): void
    {
        self::user('alice', 'alice-subject');
        self::stores()->rotate(TenantScopedEncrypter::scope(self::tenant()->slug, self::FAMILY));
        self::user('bob', 'bob-subject');
    }

    private function aProcessThatOpenedNothing(): void
    {
        self::ensureKernelShutdown();
        self::bootKernel();
        self::kms()->forget();
    }

    private static function rowsOfTheTenant(): int
    {
        $rows = self::entityManager()
            ->getConnection()
            ->fetchOne(
                'SELECT COUNT(*) FROM ' . TenantDataKeyStores::TABLE . ' WHERE scope LIKE ?',
                [self::tenant()->slug . TenantScopedEncrypter::SEPARATOR . '%'],
                [ParameterType::STRING],
            );
        static::assertIsNumeric($rows);

        return (int) $rows;
    }

    private static function opening(): DataKeysOfTheTenant
    {
        return self::service(DataKeysOfTheTenant::class, DataKeysOfTheTenant::class);
    }

    private static function stores(): TenantDataKeyStores
    {
        return self::service('beffroi.data_keys', TenantDataKeyStores::class);
    }

    private static function users(): UserRepositoryInterface
    {
        return self::service('test.beffroi.users', UserRepositoryInterface::class);
    }

    private static function kms(): CountingKms
    {
        return self::service(CountingKms::class, CountingKms::class);
    }
}
