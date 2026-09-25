<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Http\Account;

use function array_map;
use Heidi\Bundle\Http\Account\AccountSectionInterface;
use Heidi\Bundle\Http\Account\AccountSections;
use Heidi\Bundle\Http\Account\AccountSectionState;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Tests\Fixture\Fixtures;
use LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The pages of the account the home page offers (architecture §5.2): the ones that are wired, in the order
 * they are wired, each saying what the account holds there.
 */
final class AccountSectionsTest extends TestCase
{
    #[Test]
    public function thePagesAreTheOnesWiredInTheOrderTheyAreWired(): void
    {
        // Given
        $sections = new AccountSections([
            self::section('heidi_interaction_account_passkeys', 'passkeys.title', 'account.passkeys.state'),
            self::section('heidi_interaction_account_two_factor', 'two_factor.title', 'account.two_factor.state.none'),
        ]);

        // When
        $lines = $sections->of(Fixtures::user());

        // Then
        static::assertSame(
            [
                ['route' => 'heidi_interaction_account_passkeys', 'title' => 'passkeys.title'],
                ['route' => 'heidi_interaction_account_two_factor', 'title' => 'two_factor.title'],
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
            self::section('heidi_interaction_account_passkeys', 'passkeys.title', 'account.passkeys.state', [
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
        $this->expectExceptionMessageIs('Two sections of the account name the route "heidi_interaction_account_passkeys".');

        // When
        new AccountSections([
            self::section('heidi_interaction_account_passkeys', 'passkeys.title', 'account.passkeys.state'),
            self::section('heidi_interaction_account_passkeys', 'other.title', 'other.state'),
        ]);
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
