<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\AuthorizationDetails;

use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetail;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function array_column;
use function iterator_to_array;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 9396 §2
 */
final class AuthorizationDetailsTest extends TestCase
{
    private const string TYPE = 'account_information';

    #[Test]
    public function aSetHoldsAtLeastOneDetail(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A set of authorization details holds at least one detail (RFC 9396 section 2).');

        // When
        new AuthorizationDetails([]);
    }

    #[Test]
    public function aDetailAskedForTwiceCountsOnce(): void
    {
        // Given
        $detail = self::detail('acct-4711');

        // When
        $details = new AuthorizationDetails([$detail, self::detail('acct-0815'), $detail]);

        // Then
        static::assertCount(2, $details);
        static::assertSame(['acct-4711', 'acct-0815'], array_column($details->toClaim(), 'account'));
    }

    #[Test]
    public function aSetHoldsWhatItWasGiven(): void
    {
        // Given
        $details = new AuthorizationDetails([self::detail('acct-4711')]);

        // When / Then
        static::assertTrue($details->has(self::detail('acct-4711')));
    }

    #[Test]
    public function aSetDoesNotHoldADetailItWasNotGiven(): void
    {
        // Given
        $details = new AuthorizationDetails([self::detail('acct-4711')]);

        // When / Then
        static::assertFalse($details->has(self::detail('acct-0815')));
    }

    /**
     * RFC 9396 §7
     */
    #[Test]
    public function aSetCoversASubsetOfItself(): void
    {
        // Given
        $details = new AuthorizationDetails([self::detail('acct-4711'), self::detail('acct-0815')]);

        // When / Then
        static::assertTrue($details->covers(new AuthorizationDetails([self::detail('acct-0815')])));
    }

    #[Test]
    public function aSetDoesNotCoverADetailItDoesNotHold(): void
    {
        // Given
        $details = new AuthorizationDetails([self::detail('acct-4711')]);

        // When / Then
        static::assertFalse($details->covers(new AuthorizationDetails([self::detail('acct-4711'), self::detail('acct-0815')])));
    }

    /**
     * Architecture §4.3
     */
    #[Test]
    public function mergingTwoSetsKeepsBothAndEachDetailOnce(): void
    {
        // Given
        $held = new AuthorizationDetails([self::detail('acct-4711')]);

        // When
        $merged = $held->mergedWith(new AuthorizationDetails([self::detail('acct-4711'), self::detail('acct-0815')]));

        // Then
        static::assertCount(2, $merged);
        static::assertSame(['acct-4711', 'acct-0815'], array_column($merged->toClaim(), 'account'));
    }

    #[Test]
    public function theTypesOfASetAreNamedOnceInTheOrderTheyWereFirstSeen(): void
    {
        // Given
        $details = new AuthorizationDetails([
            self::detail('acct-4711'),
            new AuthorizationDetail('payment_initiation', [
                'amount' => '17.00',
            ]),
            self::detail('acct-0815'),
        ]);

        // When / Then
        static::assertSame([self::TYPE, 'payment_initiation'], $details->types());
    }

    /**
     * RFC 9396 §7, §9
     */
    #[Test]
    public function theClaimIsTheArrayOfTheObjects(): void
    {
        // Given
        $details = new AuthorizationDetails([self::detail('acct-4711')]);

        // When / Then
        static::assertSame(
            [
                [
                    'type' => self::TYPE,
                    'account' => 'acct-4711',
                ],
            ],
            $details->toClaim(),
        );
    }

    #[Test]
    public function twoSetsHoldingTheSameDetailsInAnyOrderAreEqual(): void
    {
        // Given
        $details = new AuthorizationDetails([self::detail('acct-4711'), self::detail('acct-0815')]);

        // When / Then
        static::assertTrue($details->equals(new AuthorizationDetails([self::detail('acct-0815'), self::detail('acct-4711')])));
    }

    #[Test]
    public function aSetIsIteratedInTheOrderItWasGiven(): void
    {
        // Given
        $details = new AuthorizationDetails([self::detail('acct-4711'), self::detail('acct-0815')]);

        // When / Then
        static::assertSame($details->all, iterator_to_array($details));
    }

    private static function detail(string $account): AuthorizationDetail
    {
        return new AuthorizationDetail(self::TYPE, [
            'account' => $account,
        ]);
    }
}
