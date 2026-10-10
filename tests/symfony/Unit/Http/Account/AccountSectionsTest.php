<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Http\Account;

use function array_map;
use Beffroi\Bundle\Http\Account\AccountSectionInterface;
use Beffroi\Bundle\Http\Account\AccountSections;
use Beffroi\Bundle\Http\Account\AccountSectionState;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Tests\Fixture\Fixtures;
use LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The pages of the account the home page offers (architecture §5.2): the ones that are wired, in the order
 * they are wired, each saying what the account holds there. The same list without what the account holds,
 * for a navigation of those pages, and what it holds in one of them.
 */
final class AccountSectionsTest extends TestCase
{
    #[Test]
    public function thePagesAreTheOnesWiredInTheOrderTheyAreWired(): void
    {
        // Given
        $sections = new AccountSections([
            self::section('beffroi_interaction_account_passkeys', 'passkeys.title', 'account.passkeys.state'),
            self::section('beffroi_interaction_account_two_factor', 'two_factor.title', 'account.two_factor.state.none'),
        ]);

        // When
        $lines = $sections->of(Fixtures::user());

        // Then
        static::assertSame(
            [
                ['route' => 'beffroi_interaction_account_passkeys', 'title' => 'passkeys.title'],
                ['route' => 'beffroi_interaction_account_two_factor', 'title' => 'two_factor.title'],
            ],
            array_map(static fn (array $line): array => [
                'route' => $line['route'],
                'title' => $line['title'],
            ], $lines),
        );
    }

    #[Test]
    public function eachPageCarriesWhatTheSectionSaysOfTheUser(): void
    {
        // Given
        $sections = new AccountSections([
            self::section('beffroi_interaction_account_passkeys', 'passkeys.title', 'account.passkeys.state', [
                'count' => 2,
            ]),
        ]);

        // When
        $lines = $sections->of(Fixtures::user());

        // Then
        static::assertSame('account.passkeys.state', $lines[0]['state']->key);
        static::assertSame(
            [
                'count' => 2,
            ],
            $lines[0]['state']->parameters,
        );
    }

    #[Test]
    public function twoSectionsOnOneRouteAreAFaultOfTheWiring(): void
    {
        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('Two sections of the account name the route "beffroi_interaction_account_passkeys".');

        // When
        new AccountSections([
            self::section('beffroi_interaction_account_passkeys', 'passkeys.title', 'account.passkeys.state'),
            self::section('beffroi_interaction_account_passkeys', 'other.title', 'other.state'),
        ]);
    }

    #[Test]
    public function aNavigationReadsWhereThePagesAreAndWhatTheyAreCalled(): void
    {
        // Given
        $sections = new AccountSections([
            self::section('beffroi_interaction_account_passkeys', 'passkeys.title', 'account.passkeys.state'),
            self::section('beffroi_interaction_account_two_factor', 'two_factor.title', 'account.two_factor.state.none'),
        ]);

        // When / Then
        static::assertSame(
            [
                ['route' => 'beffroi_interaction_account_passkeys', 'title' => 'passkeys.title'],
                ['route' => 'beffroi_interaction_account_two_factor', 'title' => 'two_factor.title'],
            ],
            $sections->pages(),
        );
    }

    /**
     * A navigation is on every page of the plane, where the home of the account is read once: it asks where
     * the pages are, and never what the account holds in each of them.
     */
    #[Test]
    public function aNavigationAsksNoSectionWhatTheAccountHolds(): void
    {
        // Given
        $section = $this->createMock(AccountSectionInterface::class);
        $section->method('route')->willReturn('beffroi_interaction_account_passkeys');
        $section->method('title')->willReturn('passkeys.title');

        // Then
        $section->expects(static::never())->method('state');

        // When
        new AccountSections([$section])->pages();
    }

    #[Test]
    public function whatTheAccountHoldsInOnePageIsAskedOfTheSectionOnThatRoute(): void
    {
        // Given
        $sections = new AccountSections([
            self::section('beffroi_interaction_account_passkeys', 'passkeys.title', 'account.passkeys.state', [
                'count' => 2,
            ]),
            self::section('beffroi_interaction_account_two_factor', 'two_factor.title', 'account.two_factor.state.none'),
        ]);

        // When
        $state = $sections->stateOf('beffroi_interaction_account_passkeys', Fixtures::user());

        // Then
        static::assertNotNull($state);
        static::assertSame('account.passkeys.state', $state->key);
        static::assertSame(
            [
                'count' => 2,
            ],
            $state->parameters,
        );
    }

    #[Test]
    public function aRouteNoSectionIsOnHoldsNothing(): void
    {
        // Given
        $sections = new AccountSections([
            self::section('beffroi_interaction_account_passkeys', 'passkeys.title', 'account.passkeys.state'),
        ]);

        // When / Then
        static::assertNull($sections->stateOf('beffroi_interaction_account_two_factor', Fixtures::user()));
    }

    /**
     * @param array<string, string|int> $parameters
     */
    private static function section(string $route, string $title, string $stateKey, array $parameters = []): AccountSectionInterface
    {
        return new readonly class($route, $title, $stateKey, $parameters) implements AccountSectionInterface {
            /**
             * @param array<string, string|int> $parameters
             */
            public function __construct(
                private string $route,
                private string $title,
                private string $stateKey,
                private array $parameters,
            ) {
            }

            public function route(): string
            {
                return $this->route;
            }

            public function title(): string
            {
                return $this->title;
            }

            public function state(User $user): AccountSectionState
            {
                return new AccountSectionState($this->stateKey, $this->parameters);
            }
        };
    }
}
