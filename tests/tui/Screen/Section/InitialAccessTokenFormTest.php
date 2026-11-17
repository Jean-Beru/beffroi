<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Screen\Section;

use Beffroi\Tui\Screen\Section\InitialAccessTokenForm;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7591 §1.2, Decision 0038: the form asks for an initial access token with what the administration API issues one
 * from, the rest left to the API to refuse in its own words.
 */
final class InitialAccessTokenFormTest extends TestCase
{
    #[Test]
    public function aTokenIsAskedForOneRegistrationOverThirtyDaysUntilChanged(): void
    {
        // Given
        $form = new InitialAccessTokenForm();

        // When
        $form->write('name', ' The laptop of the second floor ');

        // Then
        static::assertSame(
            ['name' => 'The laptop of the second floor', 'registrations' => 1, 'days' => 30, 'administration' => false],
            $form->asked(),
        );
    }

    #[Test]
    #[DataProvider('provideNumbersTyped')]
    public function aNumberTypedIsSentAsTheApiReadsIt(string $typed, int|string $sent): void
    {
        // Given
        $form = new InitialAccessTokenForm();

        // When
        $form->write('days', $typed);

        // Then
        static::assertSame($sent, $form->asked()['days']);
    }

    /**
     * @return iterable<string, array{string, int|string}>
     */
    public static function provideNumbersTyped(): iterable
    {
        yield 'a whole number' => ['7', 7];
        yield 'a whole number between spaces' => [' 90 ', 90];
        yield 'a word, sent for the API to refuse' => ['seven', 'seven'];
        yield 'nothing, sent for the API to refuse' => ['', ''];
    }

    #[Test]
    public function theApisTypedBetweenCommasAreWhatTheTokenGives(): void
    {
        // Given
        $form = new InitialAccessTokenForm();

        // When
        $form->write('resources', ' https://api.example/invoices, ,https://api.example/orders ');

        // Then
        static::assertSame(['resources' => ['https://api.example/invoices', 'https://api.example/orders']], $form->asked()['granted'] ?? null);
    }

    #[Test]
    public function theAdministrationIsTurnedOverRatherThanTyped(): void
    {
        // Given
        $form = new InitialAccessTokenForm();
        $form->write('administration', 'yes');

        // When
        $form->turnOver('administration');

        // Then
        static::assertTrue($form->asked()['administration']);
    }

    #[Test]
    public function eachRowNamesItsMember(): void
    {
        // Given
        $form = new InitialAccessTokenForm();

        // When
        $members = [$form->member(0), $form->member(1), $form->member(2), $form->member(3), $form->member(4), $form->member(5)];

        // Then
        static::assertSame(['name', 'registrations', 'days', 'administration', 'resources', null], $members);
    }
}
