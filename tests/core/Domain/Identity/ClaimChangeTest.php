<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Identity;

use Beffroi\Core\Domain\Identity\ClaimChange;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * Issue #482: what a claim of a person used to say, and what they made it say.
 */
final class ClaimChangeTest extends TestCase
{
    #[Test]
    public function aChangeHoldsBothValuesAndTheTenantOfThePerson(): void
    {
        // Given
        $user = Fixtures::user();

        // When
        $change = self::change($user, 'Ada', 'Augusta');

        // Then
        static::assertSame('Ada', $change->was);
        static::assertSame('Augusta', $change->became);
        static::assertTrue($change->tenant->equals($user->tenant));
    }

    /**
     * Null on either side is a claim that said nothing: a person filling one in for the first time, or
     * taking back what they had said.
     */
    #[Test]
    #[DataProvider('provideOneSide')]
    public function aClaimFilledInOrTakenBackIsAChange(?string $was, ?string $became): void
    {
        // When / Then
        static::assertSame($was, self::change(null, $was, $became)->was);
    }

    /**
     * @return iterable<string, array{string|null, string|null}>
     */
    public static function provideOneSide(): iterable
    {
        yield 'filled in for the first time' => [null, 'Ada'];
        yield 'taken back' => ['Ada', null];
    }

    #[Test]
    public function aClaimThatSaidNothingAndSaysNothingDidNotChange(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('A change of a claim is a change');

        // When
        self::change(null, null, null);
    }

    #[Test]
    public function aValueThatDidNotChangeIsNotAChange(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('the value it had and the value it has are the same');

        // When
        self::change(null, 'Ada', 'Ada');
    }

    #[Test]
    public function aChangeNamesTheClaimItIsAbout(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A change of a claim names the claim.');

        // When
        new ClaimChange(Uuid::v7(), Fixtures::user(), '', 'Ada', 'Augusta', Fixtures::now(), Fixtures::context());
    }

    private static function change(?User $user, ?string $was, ?string $became): ClaimChange
    {
        return new ClaimChange(
            Uuid::v7(),
            $user ?? Fixtures::user(),
            'nickname',
            $was,
            $became,
            Fixtures::now(),
            Fixtures::context(),
        );
    }
}
