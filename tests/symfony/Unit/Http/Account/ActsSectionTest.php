<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Http\Account;

use App\Http\Account\ActsSection;
use function array_fill;
use Beffroi\Core\Domain\Event\AuthenticationFailed;
use Beffroi\Core\Domain\Event\AuthenticationSessionEnded;
use Beffroi\Core\Domain\Event\CredentialEnrolled;
use Beffroi\Core\Domain\Event\PasswordUsed;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordedActs;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * What the home of the account says of its acts (issue #842): how many of the last attempts to sign in as
 * the person were refused, and not how many refusals the journal holds.
 */
final class ActsSectionTest extends TestCase
{
    #[Test]
    public function anAccountNobodyTriedToSignInToIsSaidToHoldNoRefusal(): void
    {
        // Given
        $user = Fixtures::user();
        $section = self::section($user, []);

        // When
        $state = $section->state($user);

        // Then
        static::assertSame('account.acts.state', $state->key);
        static::assertSame(
            [
                'count' => 0,
            ],
            $state->parameters,
        );
    }

    #[Test]
    public function theRefusalsAmongTheLastAttemptsAreCounted(): void
    {
        // Given
        $user = Fixtures::user();
        $section = self::section($user, [
            AuthenticationFailed::NAME,
            UserAuthenticated::NAME,
            AuthenticationFailed::NAME,
        ]);

        // When
        $state = $section->state($user);

        // Then
        static::assertSame(
            [
                'count' => 2,
            ],
            $state->parameters,
        );
    }

    /**
     * The card says that somebody tried and did not recently, and what bounds "recently" is a number of
     * attempts: a refusal the person has signed in past that many times is behind them, and of a long run
     * of refusals only those the last attempts still hold are counted.
     *
     * @param list<string> $acts the oldest first
     */
    #[Test]
    #[DataProvider('provideTheLastAttempts')]
    public function onlyTheRefusalsTheLastAttemptsHoldAreCounted(array $acts, int $refused): void
    {
        // Given
        $user = Fixtures::user();
        $section = self::section($user, $acts);

        // When
        $state = $section->state($user);

        // Then
        static::assertSame(
            [
                'count' => $refused,
            ],
            $state->parameters,
        );
    }

    /**
     * @return iterable<string, array{list<string>, int}>
     */
    public static function provideTheLastAttempts(): iterable
    {
        yield 'a refusal followed by as many sign-ins as the card reads' => [
            [AuthenticationFailed::NAME, ...array_fill(0, ActsSection::AMONG_THE_LAST, UserAuthenticated::NAME)],
            0,
        ];
        yield 'a refusal followed by one sign-in fewer' => [
            [AuthenticationFailed::NAME, ...array_fill(0, ActsSection::AMONG_THE_LAST - 1, UserAuthenticated::NAME)],
            1,
        ];
        yield 'more refusals than the card reads, then five sign-ins' => [
            [
                ...array_fill(0, ActsSection::AMONG_THE_LAST + 5, AuthenticationFailed::NAME),
                ...array_fill(0, 5, UserAuthenticated::NAME),
            ],
            ActsSection::AMONG_THE_LAST - 5,
        ];
    }

    /**
     * A proof is how a sign-in got in and not an attempt of its own, and the other acts of an account are
     * nobody trying: however many of them follow a refusal, they push it out of nothing.
     */
    #[Test]
    #[DataProvider('provideActsThatAreNoAttempt')]
    public function anActThatIsNoAttemptTakesNoPlaceAmongTheLastAttempts(string $act): void
    {
        // Given
        $user = Fixtures::user();
        $section = self::section($user, [AuthenticationFailed::NAME, ...array_fill(0, ActsSection::AMONG_THE_LAST, $act)]);

        // When
        $state = $section->state($user);

        // Then
        static::assertSame(
            [
                'count' => 1,
            ],
            $state->parameters,
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideActsThatAreNoAttempt(): iterable
    {
        yield 'a proof of a sign-in' => [PasswordUsed::NAME];
        yield 'a session that ended' => [AuthenticationSessionEnded::NAME];
        yield 'a credential enrolled' => [CredentialEnrolled::NAME];
    }

    /**
     * @param list<string> $acts the acts of that person, the oldest first
     */
    private static function section(User $user, array $acts): ActsSection
    {
        $journal = new RecordedActs();
        foreach ($acts as $act) {
            $journal->record(new JournalEntry(Uuid::v7(), $user->tenant, $act, Fixtures::now(), Fixtures::context(), $user->subject));
        }

        return new ActsSection($journal);
    }
}
