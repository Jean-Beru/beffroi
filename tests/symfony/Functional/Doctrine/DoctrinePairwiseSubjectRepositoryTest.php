<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Oidc\Domain\Claims\PairwiseSubject;
use Beffroi\Oidc\Domain\Claims\SectorIdentifier;
use Beffroi\Oidc\Port\PairwiseSubjectRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Uid\Uuid;

/**
 * OIDC Core §8.1, Architecture §5.3
 */
final class DoctrinePairwiseSubjectRepositoryTest extends DatabaseTestCase
{
    private const string SECTOR = 'rp.example';

    private const string IDENTIFIER = 'ZjgzT0ozRDJ4RjFCZzh2dWI5dExlMWdITXpWNzZlOFR1czl1UEh2UlZFVQ';

    #[Test]
    public function anIdentifierItRecordedNamesItsUser(): void
    {
        // Given
        $alice = self::user();
        self::assigned()->record(self::subjectOf($alice->subject));
        self::reload();

        // When
        $found = self::assigned()->findUser(self::tenant(), new SectorIdentifier(self::SECTOR), new Subject(self::IDENTIFIER));

        // Then
        static::assertTrue($found?->id->equals($alice->id));
    }

    #[Test]
    public function anIdentifierOfOneSectorNamesNobodyInAnother(): void
    {
        // Given
        self::assigned()->record(self::subjectOf(self::user()->subject));
        self::reload();

        // When
        $found = self::assigned()->findUser(self::tenant(), new SectorIdentifier('elsewhere.example'), new Subject(self::IDENTIFIER));

        // Then
        static::assertNull($found);
    }

    #[Test]
    public function aValueItNeverRecordedNamesNobody(): void
    {
        // Given
        self::user();

        // When
        $found = self::assigned()->findUser(self::tenant(), new SectorIdentifier(self::SECTOR), new Subject('a-value-nobody-was-handed'));

        // Then
        static::assertNull($found);
    }

    #[Test]
    public function recordingTheSameIdentifierAgainChangesNothing(): void
    {
        // Given
        $alice = self::user();
        $first = self::subjectOf($alice->subject);
        self::assigned()->record($first);

        // When
        self::assigned()->record(self::subjectOf($alice->subject));
        self::reload();

        // Then
        $found = self::assigned()->findUser(self::tenant(), new SectorIdentifier(self::SECTOR), new Subject(self::IDENTIFIER));
        static::assertTrue($found?->id->equals($alice->id));
    }

    private static function subjectOf(Subject $of): PairwiseSubject
    {
        $user = self::service('test.beffroi.users', UserRepositoryInterface::class)
            ->findBySubject(self::tenant(), $of) ?? static::fail('The user was not stored.');

        return new PairwiseSubject(
            Uuid::v7(),
            $user,
            new SectorIdentifier(self::SECTOR),
            new Subject(self::IDENTIFIER),
            self::now(),
        );
    }

    private static function assigned(): PairwiseSubjectRepositoryInterface
    {
        return self::service('test.beffroi.pairwise_subjects', PairwiseSubjectRepositoryInterface::class);
    }
}
