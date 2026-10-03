<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Doctrine;

use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\RawRows;
use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\SealedRows;
use Beffroi\Core\Domain\Identity\ClaimChange;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\ChangesOfAPersonInterface;
use Beffroi\Core\Port\ClaimHistoryInterface;
use Doctrine\DBAL\Connection;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use Symfony\Component\Uid\Uuid;

/**
 * Issue #482 and decision 0011: what a claim of a person used to say is a personal datum as much as what
 * it says now, so both are sealed under the data key of the tenant, in a family of their own, and the
 * provenance of the request that changed them with them.
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
     * The name of the claim is in the clear: it is a name of OIDC Core §5.1 and never a value, and it is
     * what a reading of one person's history filters on.
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
