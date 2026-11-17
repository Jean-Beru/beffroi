<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Screen\Section;

use Beffroi\Tui\Json\Document;
use Beffroi\Tui\Screen\Section\AccountForm;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7396 §2: the form writes the members changed, and only them, where the document of a person holds them.
 */
final class AccountFormTest extends TestCase
{
    #[Test]
    public function eachMemberChangedIsWrittenWhereTheDocumentOfThePersonHoldsIt(): void
    {
        // Given
        $form = new AccountForm(self::alice());

        // When
        $form->write('username', 'ali');
        $form->write('given_name', 'Alice');
        $form->write('address.locality', 'Lyon');

        // Then
        static::assertSame(
            ['username' => 'ali', 'claims' => ['given_name' => 'Alice', 'address' => ['locality' => 'Lyon']]],
            $form->patch(),
        );
    }

    #[Test]
    public function anEmptyValueTakesTheMemberAway(): void
    {
        // Given
        $form = new AccountForm(self::alice());

        // When
        $form->write('name', '  ');

        // Then
        static::assertSame(['claims' => ['name' => null]], $form->patch());
    }

    #[Test]
    public function aValueTypedAsThePersonHoldsItIsNoChange(): void
    {
        // Given
        $form = new AccountForm(self::alice());
        $form->write('name', 'Alice Pleasance Liddell');

        // When
        $form->write('name', 'Alice Liddell');

        // Then
        static::assertSame([false, []], [$form->isChanged(), $form->patch()]);
    }

    #[Test]
    public function aVerificationTheDocumentDoesNotSayIsTurnedOverToAYes(): void
    {
        // Given
        $form = new AccountForm(self::alice());

        // When
        $form->turnOver('phone_number_verified');

        // Then
        static::assertSame(['claims' => ['phone_number_verified' => true]], $form->patch());
    }

    #[Test]
    public function aVerificationTurnedOverTwiceIsNoChange(): void
    {
        // Given
        $form = new AccountForm(self::alice());
        $form->turnOver('email_verified');

        // When
        $form->turnOver('email_verified');

        // Then
        static::assertFalse($form->isChanged());
    }

    #[Test]
    public function theFieldOfAMemberStartsWithTheValueThePersonHolds(): void
    {
        // Given
        $form = new AccountForm(self::alice());

        // When
        $text = $form->text('address.locality');

        // Then
        static::assertSame('Paris', $text);
    }

    private static function alice(): Document
    {
        return new Document([
            'id' => '0193-alice',
            'username' => 'alice',
            'claims' => [
                'name' => 'Alice Liddell',
                'email' => 'alice@example.com',
                'email_verified' => true,
                'address' => ['locality' => 'Paris'],
            ],
        ]);
    }
}
