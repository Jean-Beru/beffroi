<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\AtomicWritesInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;
use Symfony\Component\Uid\Uuid;

final class DoctrineAtomicWritesTest extends DatabaseTestCase
{
    #[Test]
    public function writesThatAllSucceedAreAllKept(): void
    {
        // Given
        $alice = User::create(Uuid::v7(), self::tenant(), new Subject('alice-subject'), 'alice', self::now());
        $bob = User::create(Uuid::v7(), self::tenant(), new Subject('bob-subject'), 'bob', self::now());

        // When
        self::writes()
            ->atomically(static function () use ($alice, $bob): void {
                self::users()->save($alice);
                self::users()->save($bob);
            });

        // Then
        self::reload();
        static::assertNotNull(self::users()->findByUsername(self::tenant(), 'alice'));
        static::assertNotNull(self::users()->findByUsername(self::tenant(), 'bob'));
    }

    #[Test]
    public function theFailureOfAWriteGoesOnToTheCaller(): void
    {
        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageIs('The second write failed.');

        // When
        self::writes()
            ->atomically(static function (): void {
                throw new RuntimeException('The second write failed.');
            });
    }

    #[Test]
    public function aWriteThatFailsTakesTheWritesBeforeItWithIt(): void
    {
        // Given
        $alice = User::create(Uuid::v7(), self::tenant(), new Subject('alice-subject'), 'alice', self::now());

        // When
        try {
            self::writes()
                ->atomically(static function () use ($alice): void {
                    self::users()->save($alice);

                    throw new RuntimeException('The second write failed.');
                });
        } catch (RuntimeException) {
        }

        // Then
        static::assertNull(self::users()->findByUsername(self::tenant(), 'alice'));
    }

    #[Test]
    public function aWriteThatFailsLeavesNothingManaged(): void
    {
        // Given
        $alice = User::create(Uuid::v7(), self::tenant(), new Subject('alice-subject'), 'alice', self::now());

        // When
        try {
            self::writes()
                ->atomically(static function () use ($alice): void {
                    self::users()->save($alice);

                    throw new RuntimeException('The second write failed.');
                });
        } catch (RuntimeException) {
        }

        // Then
        static::assertFalse(self::entityManager()->contains($alice));
    }

    #[Test]
    public function aWriteAfterAFailureIsKept(): void
    {
        // Given
        $alice = User::create(Uuid::v7(), self::tenant(), new Subject('alice-subject'), 'alice', self::now());
        try {
            self::writes()
                ->atomically(static function () use ($alice): void {
                    self::users()->save($alice);

                    throw new RuntimeException('The second write failed.');
                });
        } catch (RuntimeException) {
        }

        // When
        self::users()->save(User::create(Uuid::v7(), self::tenant(), new Subject('bob-subject'), 'bob', self::now()));

        // Then
        static::assertNotNull(self::users()->findByUsername(self::tenant(), 'bob'));
        static::assertNull(self::users()->findByUsername(self::tenant(), 'alice'));
    }

    #[Test]
    public function aFailureLeavesTheManagerOpen(): void
    {
        // When
        try {
            self::writes()
                ->atomically(static function (): void {
                    throw new RuntimeException('Refused before anything was written.');
                });
        } catch (RuntimeException) {
        }

        // Then
        static::assertTrue(self::entityManager()->isOpen());
    }

    private static function writes(): AtomicWritesInterface
    {
        return self::service('test.beffroi.atomic_writes', AtomicWritesInterface::class);
    }

    private static function users(): UserRepositoryInterface
    {
        return self::service('test.beffroi.users', UserRepositoryInterface::class);
    }
}
