<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Identity\Claim;

use Beffroi\Core\Domain\Identity\Claim\ClaimField;
use Beffroi\Core\Exception\InvalidArgumentException;
use function array_combine;
use function array_map;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function range;

/**
 * Issues #476 and #479: what kind of field a claim is offered as, and what a closed set is closed on.
 */
final class ClaimFieldTest extends TestCase
{
    #[Test]
    #[DataProvider('provideKinds')]
    public function aFieldCarriesTheKindItWasBuiltAs(ClaimField $field, string $kind): void
    {
        // When / Then
        static::assertSame($kind, $field->kind);
    }

    /**
     * @return iterable<string, array{ClaimField, string}>
     */
    public static function provideKinds(): iterable
    {
        yield 'a line of text' => [ClaimField::text(), 'text'];
        yield 'a telephone number' => [ClaimField::telephone(), 'tel'];
        yield 'a URL' => [ClaimField::url(), 'url'];
        yield 'a date' => [ClaimField::date(), 'date'];
        yield 'one of a closed set' => [ClaimField::oneOf(['fr' => 'français']), 'text'];
    }

    /**
     * The pattern comes with a date for a browser that renders a line of text instead, where it is the
     * only check left.
     */
    #[Test]
    public function aDateCarriesThePatternAndTheExample(): void
    {
        // When
        $field = ClaimField::date('\d{4}', 'profile.birthdate.example');

        // Then
        static::assertSame('\d{4}', $field->pattern);
        static::assertSame('profile.birthdate.example', $field->example);
    }

    #[Test]
    public function aChoiceOfNothingIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A claim offered as a choice offers something to choose.');

        // When
        ClaimField::oneOf([]);
    }

    /**
     * Each value with the label a person reads it by, the name of a language in that language being the
     * only thing recognisable in a list of several hundred.
     */
    #[Test]
    public function aClosedSetCarriesALabelPerValue(): void
    {
        // When
        $field = ClaimField::oneOf([
            'fr' => 'français',
            'ja' => '日本語',
        ]);

        // Then
        static::assertSame(
            [
                'fr' => 'français',
                'ja' => '日本語',
            ],
            $field->choices,
        );
    }

    #[Test]
    public function aSetShortEnoughToReadIsChosenFromAList(): void
    {
        // When / Then
        static::assertFalse(self::setOf(ClaimField::PICKED_BEYOND)->isPicked());
    }

    #[Test]
    public function aSetLongerThanThatIsPickedFrom(): void
    {
        // When / Then
        static::assertTrue(self::setOf(ClaimField::PICKED_BEYOND + 1)->isPicked());
    }

    #[Test]
    public function aFieldWithNoClosedSetIsNotPickedFrom(): void
    {
        // When / Then
        static::assertFalse(ClaimField::text()->isPicked());
    }

    #[Test]
    public function aClosedSetHoldsTheValuesItNames(): void
    {
        // When / Then
        static::assertTrue(ClaimField::oneOf(['fr' => 'français'])->holds('fr'));
    }

    #[Test]
    public function aClosedSetDoesNotHoldAValueItDoesNotName(): void
    {
        // When / Then
        static::assertFalse(ClaimField::oneOf(['fr' => 'français'])->holds('ja'));
    }

    /**
     * Taking a value back is holdable by every field: an empty field is a person who said nothing of
     * themselves any more.
     */
    #[Test]
    #[DataProvider('provideNothing')]
    public function takingAValueBackIsHeldByAClosedSet(?string $nothing): void
    {
        // When / Then
        static::assertTrue(ClaimField::oneOf(['fr' => 'français'])->holds($nothing));
    }

    /**
     * @return iterable<string, array{string|null}>
     */
    public static function provideNothing(): iterable
    {
        yield 'nothing at all' => [null];
        yield 'an empty field' => [''];
    }

    /**
     * What the shape of a value is, where the set is not closed, stays the model's.
     */
    #[Test]
    public function aFieldWithNoClosedSetHoldsAnything(): void
    {
        // When / Then
        static::assertTrue(ClaimField::text('\d{4}')->holds('not a year at all'));
    }

    #[Test]
    public function aValueTheSetDoesNotHoldIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The value "ja" is not one this claim may hold.');

        // When
        ClaimField::oneOf(['fr' => 'français'])->assertHolds('ja');
    }

    /**
     * A date input renders a value it cannot carry empty, a year alone as much as a whole date with a
     * line feed behind it, and a save on an empty input would quietly erase what an import wrote, so
     * what is offered for such a value is a line of text.
     */
    #[Test]
    #[DataProvider('provideValuesADateInputCannotCarry')]
    public function aValueADateInputCannotCarryIsOfferedAsALineOfText(string $value): void
    {
        // When
        $field = ClaimField::date('\d{4}(-\d{2}-\d{2})?')->forHolding($value);

        // Then
        static::assertSame('text', $field->kind);
        static::assertSame('\d{4}(-\d{2}-\d{2})?', $field->pattern);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideValuesADateInputCannotCarry(): iterable
    {
        yield 'a year alone' => ['1815'];
        yield 'a line feed behind a whole date' => ["1815-12-10\n"];
    }

    #[Test]
    public function awholeDateIsOfferedAsADate(): void
    {
        // When / Then
        static::assertSame('date', ClaimField::date('\d{4}(-\d{2}-\d{2})?')->forHolding('1815-12-10')->kind);
    }

    #[Test]
    #[DataProvider('provideNothing')]
    public function aFieldHoldingNothingIsOfferedAsItself(?string $nothing): void
    {
        // When / Then
        static::assertSame('date', ClaimField::date('\d{4}')->forHolding($nothing)->kind);
    }

    /**
     * Only a kind whose input is narrower than what its claim holds has anything to fall back from.
     */
    #[Test]
    public function aLineOfTextIsOfferedAsItselfWhateverItHolds(): void
    {
        // When / Then
        static::assertSame('text', ClaimField::text('\d{4}')->forHolding('not a year at all')->kind);
    }

    private static function setOf(int $many): ClaimField
    {
        $values = array_map(static fn (int $index): string => 'value-' . $index, range(1, $many));

        return ClaimField::oneOf(array_combine($values, $values));
    }
}
