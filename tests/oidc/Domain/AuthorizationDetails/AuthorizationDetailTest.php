<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\AuthorizationDetails;

use Heidi\Oidc\Domain\AuthorizationDetails\AuthorizationDetail;
use Heidi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * One object of an "authorization_details" array (RFC 9396 §2), as the type that answers for it kept it.
 * What it is and whether two of them ask for the same thing are answered here and nowhere else.
 */
final class AuthorizationDetailTest extends TestCase
{
    private const string TYPE = 'account_information';

    #[Test]
    public function itCarriesTheTypeAndTheMembersItWasGiven(): void
    {
        // When
        $detail = new AuthorizationDetail(self::TYPE, [
            'account' => 'acct-4711',
        ]);

        // Then
        static::assertSame(self::TYPE, $detail->type);
        static::assertSame(
            [
                'account' => 'acct-4711',
            ],
            $detail->members,
        );
        static::assertSame([], $detail->rendering);
    }

    /**
     * RFC 9396 §2: a detail with no type is a detail nothing can answer for.
     */
    #[Test]
    public function aDetailNamesItsType(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An authorization detail names its type (RFC 9396 section 2).');

        // When
        new AuthorizationDetail('');
    }

    /**
     * The type is carried on its own, so a member of the same name would be a second answer to one
     * question.
     */
    #[Test]
    public function theMembersCarryNoTypeOfTheirOwn(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The members of an authorization detail of the type "account_information" carry no "type" of their own: the detail carries it.');

        // When
        new AuthorizationDetail(self::TYPE, [
            'type' => 'payment_initiation',
        ]);
    }

    /**
     * RFC 9396 §7, §9: "type" first, because that is the member a resource server reads before any other.
     */
    #[Test]
    public function theClaimNamesTheTypeFirst(): void
    {
        // Given
        $detail = new AuthorizationDetail(self::TYPE, [
            'account' => 'acct-4711',
            'actions' => ['read'],
        ]);

        // When / Then
        static::assertSame(
            [
                'type' => self::TYPE,
                'account' => 'acct-4711',
                'actions' => ['read'],
            ],
            $detail->toClaim(),
        );
    }

    #[Test]
    public function twoDetailsOfOneTypeWithTheSameMembersAreTheSameDetail(): void
    {
        // Given
        $members = [
            'account' => 'acct-4711',
        ];

        // When / Then
        static::assertTrue(new AuthorizationDetail(self::TYPE, $members)->equals(new AuthorizationDetail(self::TYPE, $members)));
    }

    /**
     * What a consent was given for is what it covers, so anything that differs at all is another detail.
     *
     * @param array<string, mixed> $members
     */
    #[Test]
    #[DataProvider('provideOtherDetails')]
    public function aDetailThatDiffersAtAllIsAnotherDetail(string $type, array $members): void
    {
        // Given
        $detail = new AuthorizationDetail(self::TYPE, [
            'account' => 'acct-4711',
            'actions' => ['read'],
        ]);

        // When / Then
        static::assertFalse($detail->equals(new AuthorizationDetail($type, $members)));
    }

    /**
     * @return iterable<string, array{string, array<string, mixed>}>
     */
    public static function provideOtherDetails(): iterable
    {
        yield 'another type' => [
            'payment_initiation',
            [
                'account' => 'acct-4711',
                'actions' => ['read'],
            ],
        ];
        yield 'another account' => [
            self::TYPE,
            [
                'account' => 'acct-0815',
                'actions' => ['read'],
            ],
        ];
        yield 'one more action' => [
            self::TYPE,
            [
                'account' => 'acct-4711',
                'actions' => ['read', 'write'],
            ],
        ];
        yield 'one member missing' => [
            self::TYPE,
            [
                'account' => 'acct-4711',
            ],
        ];
    }

    /**
     * The rendering is what a page says of the detail and not what it is: two details that ask for the
     * same thing are the same detail whatever a page would show of them.
     */
    #[Test]
    public function theRenderingIsNotWhatADetailIs(): void
    {
        // Given
        $members = [
            'account' => 'acct-4711',
        ];

        // When / Then
        static::assertTrue(new AuthorizationDetail(self::TYPE, $members, [
            'account' => 'acct-4711',
        ])->equals(new AuthorizationDetail(self::TYPE, $members)));
    }
}
