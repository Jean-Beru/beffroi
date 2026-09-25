<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Token;

use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Token\RefreshTokenFamily;
use Heidi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class RefreshTokenFamilyTest extends TestCase
{
    /**
     * Architecture §4.6: the family descends from a code.
     */
    #[Test]
    public function itDescendsFromACode(): void
    {
        // Given
        $id = Uuid::v7();

        // When
        $family = new RefreshTokenFamily($id, DrawnSecret::digestOf('the-code'), Uuid::v7(), Fixtures::now(), Fixtures::now()->modify('+90 days'));

        // Then
        static::assertSame($id, $family->id);
        static::assertSame(DrawnSecret::digestOf('the-code'), $family->grantingRecordHash);
        static::assertEquals(Fixtures::now(), $family->startedAt);
    }

    /**
     * Architecture §4.6: the family carries the absolute lifetime, ninety days, the last instant excluded.
     */
    #[Test]
    #[DataProvider('provideInstants')]
    public function itExpiresAbsolutely(string $offset, bool $expired): void
    {
        // Given
        $family = new RefreshTokenFamily(Uuid::v7(), DrawnSecret::digestOf('the-code'), Uuid::v7(), Fixtures::now(), Fixtures::now()->modify('+90 days'));

        // When / Then
        static::assertSame($expired, $family->isExpired(Fixtures::now()->modify($offset)));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideInstants(): iterable
    {
        yield 'at start' => ['+0 seconds', false];
        yield 'last second' => ['+90 days -1 second', false];
        yield 'at expiry' => ['+90 days', true];
    }

    #[Test]
    public function twoFamiliesWithTheSameIdentifierAreEqualWhateverTheRest(): void
    {
        // Given
        $id = Uuid::v7();
        $family = new RefreshTokenFamily($id, DrawnSecret::digestOf('the-code'), Uuid::v7(), Fixtures::now(), Fixtures::now()->modify('+90 days'));

        // When / Then
        static::assertTrue($family->equals(
            new RefreshTokenFamily($id, DrawnSecret::digestOf('another'), Uuid::v7(), Fixtures::now(), Fixtures::now()->modify('+1 day')),
        ));
    }

    #[Test]
    public function twoFamiliesWithDifferentIdentifiersAreNotEqual(): void
    {
        // Given
        $family = new RefreshTokenFamily(Uuid::v7(), DrawnSecret::digestOf('the-code'), Uuid::v7(), Fixtures::now(), Fixtures::now()->modify('+90 days'));

        // When / Then
        static::assertFalse($family->equals(
            new RefreshTokenFamily(Uuid::v7(), DrawnSecret::digestOf('the-code'), Uuid::v7(), Fixtures::now(), Fixtures::now()->modify('+90 days')),
        ));
    }

    #[Test]
    public function itRefusesACodeThatIsNotAHexSha256(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new RefreshTokenFamily(Uuid::v7(), 'the-code', Uuid::v7(), Fixtures::now(), Fixtures::now()->modify('+90 days'));
    }

    #[Test]
    public function itRefusesToExpireBeforeItStarted(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new RefreshTokenFamily(Uuid::v7(), DrawnSecret::digestOf('the-code'), Uuid::v7(), Fixtures::now(), Fixtures::now());
    }
}
