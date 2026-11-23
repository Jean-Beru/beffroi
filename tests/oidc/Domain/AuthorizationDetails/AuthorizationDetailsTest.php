<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\AuthorizationDetails;

use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetail;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function array_column;
use function array_map;
use function hrtime;
use function iterator_to_array;
use function range;
use PHPUnit\Framework\Attributes\DataProvider;
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

    /**
     * RFC 9396 §7
     */
    #[Test]
    #[DataProvider('provideTwoDetails')]
    public function twoDetailsCountOnceWhenTheyAreIdentical(AuthorizationDetail $first, AuthorizationDetail $second, int $count): void
    {
        // When
        $details = new AuthorizationDetails([$first, $second]);

        // Then
        static::assertCount($count, $details);
    }

    /**
     * @return iterable<string, array{AuthorizationDetail, AuthorizationDetail, int}>
     */
    public static function provideTwoDetails(): iterable
    {
        yield 'the same members' => [self::detail('acct-4711'), self::detail('acct-4711'), 1];
        yield 'the same members of another type' => [
            self::detail('acct-4711'),
            new AuthorizationDetail('payment_initiation', ['account' => 'acct-4711']),
            2,
        ];
        yield 'the same members in another order' => [
            new AuthorizationDetail(self::TYPE, ['account' => 'acct-4711', 'actions' => ['read']]),
            new AuthorizationDetail(self::TYPE, ['actions' => ['read'], 'account' => 'acct-4711']),
            2,
        ];
        yield 'the same list in another order' => [
            new AuthorizationDetail(self::TYPE, ['actions' => ['read', 'list']]),
            new AuthorizationDetail(self::TYPE, ['actions' => ['list', 'read']]),
            2,
        ];
        yield 'an integer and a float of its value' => [
            new AuthorizationDetail(self::TYPE, ['amount' => 17]),
            new AuthorizationDetail(self::TYPE, ['amount' => 17.0]),
            2,
        ];
        yield 'a number and the string that writes it' => [
            new AuthorizationDetail(self::TYPE, ['amount' => 17]),
            new AuthorizationDetail(self::TYPE, ['amount' => '17']),
            2,
        ];
        yield 'a zero and a negative zero' => [
            new AuthorizationDetail(self::TYPE, ['limits' => ['overdraft' => 0.0]]),
            new AuthorizationDetail(self::TYPE, ['limits' => ['overdraft' => -0.0]]),
            1,
        ];
    }

    #[Test]
    public function theFirstOfTwoIdenticalDetailsIsTheOneKept(): void
    {
        // Given
        $first = new AuthorizationDetail(self::TYPE, ['overdraft' => -0.0]);

        // When
        $details = new AuthorizationDetails([$first, new AuthorizationDetail(self::TYPE, ['overdraft' => 0.0])]);

        // Then
        static::assertSame($first, $details->all[0]);
    }

    #[Test]
    public function aSetOfTenThousandDetailsIsBuiltInLessThanASecond(): void
    {
        // Given
        $given = self::details(10_000);

        // When
        $start = hrtime(true);
        $details = new AuthorizationDetails($given);
        $milliseconds = (hrtime(true) - $start) / 1_000_000;

        // Then
        static::assertCount(10_000, $details);
        static::assertLessThan(1_000, $milliseconds);
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

    /**
     * RFC 9396 §7
     */
    #[Test]
    #[DataProvider('provideAskedDetails')]
    public function aSetCoversADetailIdenticalToOneItHolds(AuthorizationDetail $asked, bool $covers): void
    {
        // Given
        $details = new AuthorizationDetails([new AuthorizationDetail(self::TYPE, ['account' => 'acct-4711', 'overdraft' => 0.0])]);

        // When / Then
        static::assertSame($covers, $details->covers(new AuthorizationDetails([$asked])));
    }

    /**
     * @return iterable<string, array{AuthorizationDetail, bool}>
     */
    public static function provideAskedDetails(): iterable
    {
        yield 'the same members' => [new AuthorizationDetail(self::TYPE, ['account' => 'acct-4711', 'overdraft' => 0.0]), true];
        yield 'a negative zero' => [new AuthorizationDetail(self::TYPE, ['account' => 'acct-4711', 'overdraft' => -0.0]), true];
        yield 'an integer zero' => [new AuthorizationDetail(self::TYPE, ['account' => 'acct-4711', 'overdraft' => 0]), false];
        yield 'the members in another order' => [new AuthorizationDetail(self::TYPE, ['overdraft' => 0.0, 'account' => 'acct-4711']), false];
    }

    #[Test]
    public function aSetCoversAnotherOfTenThousandDetailsInLessThanASecond(): void
    {
        // Given
        $held = new AuthorizationDetails(self::details(10_000));
        $asked = new AuthorizationDetails(self::details(10_000));

        // When
        $start = hrtime(true);
        $covers = $held->covers($asked);
        $milliseconds = (hrtime(true) - $start) / 1_000_000;

        // Then
        static::assertTrue($covers);
        static::assertLessThan(1_000, $milliseconds);
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

    /**
     * @return list<AuthorizationDetail>
     */
    private static function details(int $count): array
    {
        return array_map(
            static fn (int $index): AuthorizationDetail => new AuthorizationDetail(self::TYPE, [
                'account' => 'acct-' . $index,
                'actions' => ['read', 'list'],
                'limits' => ['overdraft' => 1.5],
            ]),
            range(1, $count),
        );
    }
}
