<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use App\Tests\Symfony\Functional\Doctrine\PersonalData\RawRows;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\SealedRows;
use Beffroi\Core\Domain\Identity\ClaimChange;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\ChangesOfAPersonInterface;
use Beffroi\Core\Port\ClaimHistoryInterface;
use Doctrine\DBAL\Connection;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0011
 */
final class ClaimChangeColumnsTest extends DatabaseTestCase
{
    private const string WAS = SealedRows::VALUES['beffroi_claim_change']['was'];

    private const string BECAME = SealedRows::VALUES['beffroi_claim_change']['became'];

    #[Test]
    public function bothValuesAreReadBackAsTheyWereWritten(): void
    {
        // Given
        $user = self::user();
        self::history()->record(self::change($user));
        self::reload();

        // When
        $read = self::changes()->lastOf(self::reread($user), 10);

        // Then
        static::assertCount(1, $read);
        static::assertSame(self::WAS, $read[0]->was);
        static::assertSame(self::BECAME, $read[0]->became);
        static::assertSame(SealedRows::USER_AGENT, $read[0]->context->userAgent);
    }

    #[Test]
    public function theColumnsHoldNeitherValue(): void
    {
        // Given
        self::history()->record(self::change(self::user()));
        self::reload();

        // When
        $row = self::row();

        // Then
        static::assertStringNotContainsString(self::WAS, $row['was']);
        static::assertStringNotContainsString(self::BECAME, $row['became']);
        static::assertStringNotContainsString(SealedRows::USER_AGENT, $row['context']);
    }

    /**
     * OIDC Core §5.1
     */
    #[Test]
    public function theNameOfTheClaimIsInTheClear(): void
    {
        // Given
        self::history()->record(self::change(self::user()));
        self::reload();

        // When / Then
        static::assertSame('nickname', self::row()['claim']);
    }

    /**
     * @return iterable<string, array{string|null}>
     */
    public static function authors(): iterable
    {
        yield 'a change the person made' => [null];
        yield 'a change an administrator made' => ['administrator-subject'];
    }

    /**
     * Decision 0038
     */
    #[Test]
    #[DataProvider('authors')]
    public function whoMadeAChangeIsReadBackAsItWasWritten(?string $author): void
    {
        // Given
        $user = self::user();
        self::history()
            ->record(new ClaimChange(
                Uuid::v7(),
                $user,
                'nickname',
                self::WAS,
                self::BECAME,
                self::now(),
                self::context(),
                $author === null ? null : new Subject($author),
            ));
        self::reload();

        // When
        $read = self::changes()->lastOf(self::reread($user), 10);

        // Then
        static::assertSame($author, $read[0]->author?->value);
    }

    /**
     * @return array<string, string>
     */
    private static function row(): array
    {
        $rows = RawRows::of(self::connection(), 'beffroi_claim_change', ['claim', 'was', 'became', 'context']);
        static::assertCount(1, $rows);

        $row = [];
        foreach ($rows[0] as $column => $value) {
            $row[$column] = $value ?? static::fail(sprintf('beffroi_claim_change.%s holds nothing.', $column));
        }

        return $row;
    }

    private static function change(User $user): ClaimChange
    {
        return new ClaimChange(Uuid::v7(), $user, 'nickname', self::WAS, self::BECAME, self::now(), self::context());
    }

    private static function reread(User $user): User
    {
        $reread = self::entityManager()->find(User::class, $user->id);
        static::assertInstanceOf(User::class, $reread);

        return $reread;
    }

    private static function history(): ClaimHistoryInterface
    {
        return self::service('test.beffroi.claim_history', ClaimHistoryInterface::class);
    }

    private static function changes(): ChangesOfAPersonInterface
    {
        return self::service('test.beffroi.changes', ChangesOfAPersonInterface::class);
    }

    private static function connection(): Connection
    {
        return self::entityManager()->getConnection();
    }
}
