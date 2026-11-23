<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use Beffroi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Port\InitialAccessTokenRepositoryInterface;
use function is_numeric;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 7591 §3, Decision 0009
 */
final class DoctrineInitialAccessTokenRepositoryTest extends DatabaseTestCase
{
    #[Test]
    public function aFlushAfterASpendLeavesTheCountTheStoreHolds(): void
    {
        // Given
        $digest = self::issued(2);
        $token = self::tokens()->findByDigest(self::tenant(), $digest) ?? static::fail('The token was not stored.');
        self::tokens()->spend($token, self::now());
        self::spentByAnotherRequest($digest);

        // When
        self::entityManager()->flush();

        // Then
        static::assertSame(2, self::servedInTheStore($digest));
    }

    #[Test]
    public function aSpendLeavesTheCountTheStoreHoldsOnTheToken(): void
    {
        // Given
        $digest = self::issued(2);
        $token = self::tokens()->findByDigest(self::tenant(), $digest) ?? static::fail('The token was not stored.');
        self::spentByAnotherRequest($digest);

        // When
        self::tokens()->spend($token, self::now());

        // Then
        static::assertSame(2, $token->registrationsServed);
    }

    #[Test]
    public function aTokenSpentAsOftenAsItAllowsIsRefused(): void
    {
        // Given
        $digest = self::issued(1);
        $token = self::tokens()->findByDigest(self::tenant(), $digest) ?? static::fail('The token was not stored.');
        self::spentByAnotherRequest($digest);

        // When / Then
        static::assertFalse(self::tokens()->spend($token, self::now()));
    }

    private static function issued(int $registrationsAllowed): string
    {
        $digest = DrawnSecret::digestOf(Secrets::draw());
        self::tokens()
            ->save(new InitialAccessToken(
                Uuid::v7(),
                self::tenant(),
                $digest,
                'registrations of the suite',
                $registrationsAllowed,
                self::now(),
                self::now()->modify('+1 day'),
            ));
        self::reload();

        return $digest;
    }

    /**
     * What the spend() of a concurrent request writes: the row, and nothing this request's manager holds.
     */
    private static function spentByAnotherRequest(string $digest): void
    {
        self::entityManager()
            ->getConnection()
            ->executeStatement(
                'UPDATE beffroi_initial_access_token SET registrations_served = registrations_served + 1 WHERE digest = ?',
                [$digest],
            );
    }

    private static function servedInTheStore(string $digest): int
    {
        $served = self::entityManager()->getConnection()->fetchOne('SELECT registrations_served FROM beffroi_initial_access_token WHERE digest = ?', [$digest]);

        return is_numeric($served) ? (int) $served : static::fail('The token is not in the store.');
    }

    private static function tokens(): InitialAccessTokenRepositoryInterface
    {
        return self::service('test.beffroi.initial_access_tokens', InitialAccessTokenRepositoryInterface::class);
    }
}
