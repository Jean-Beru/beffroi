<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Event;

use function array_keys;
use Beffroi\Core\Domain\Event\ConcernsAPersonInterface;
use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailed;
use Beffroi\Oidc\Domain\Event\PushedRequestRefused;
use Beffroi\Oidc\Domain\Event\RegisteredClientDeleted;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sort;

/**
 * Issue #588: an act of the protocol done in the name of a person says whose, so that the journal of that
 * person holds it. The column the journal looks an act up under is the subject of an account, and an event
 * that leaves it empty is an act in the table that nobody finds.
 *
 * Both tests read the walk through a queue the module already keeps (EventsLeaveTheProcessTest), so an
 * event added to the module is covered by existing.
 */
final class EveryActInTheNameOfAPersonNamesThemTest extends TestCase
{
    /**
     * The events of the module that name nobody, and what each one is instead. A new event is in neither
     * list until somebody puts it in one: it names the person it concerns, or it is written here with the
     * reason, and the test below is what asks.
     */
    private const array NAMES_NOBODY = [
        ClientAuthenticationFailed::class => 'a request refused before any client was authenticated names neither a client nor a person (RFC 6749 §5.2)',
        PushedRequestRefused::class => 'a reference refused at the authorization endpoint says what was refused, and nobody had been asked anything yet (RFC 9126 §4)',
        RegisteredClientDeleted::class => 'a client taken out of the register is an act of whoever registered it, in the name of no person this provider serves (RFC 7592 §2.3)',
    ];

    /**
     * The subject of the account and never the "sub" a client was answered (OIDC Core §8.1): the walk
     * builds every case from the one user of the fixtures, so what each act names is that user.
     */
    #[Test]
    #[DataProvider('actsInTheNameOfAPerson')]
    public function anActInTheNameOfAPersonNamesThemByTheSubjectOfTheirAccount(ConcernsAPersonInterface $event): void
    {
        // When / Then
        static::assertSame('alice-subject', $event->subject()?->value, $event->name());
    }

    /**
     * What keeps the first test honest: an event that forgot to name the person it concerns would simply
     * not be among its cases. So the ones that name nobody are counted, and they are the three that have
     * nobody to name.
     */
    #[Test]
    public function theOnlyEventsThatNameNobodyAreTheOnesWithNobodyToName(): void
    {
        // Given
        $expected = array_keys(self::NAMES_NOBODY);
        sort($expected);

        // When
        $silent = [];
        foreach (EventsLeaveTheProcessTest::events() as $case) {
            if (! $case[0] instanceof ConcernsAPersonInterface) {
                $silent[$case[0]::class] = true;
            }
        }
        $silent = array_keys($silent);
        sort($silent);

        // Then
        static::assertSame($expected, $silent);
    }

    /**
     * @return iterable<string, array{ConcernsAPersonInterface}>
     */
    public static function actsInTheNameOfAPerson(): iterable
    {
        foreach (EventsLeaveTheProcessTest::events() as $name => $case) {
            $event = $case[0];
            if ($event instanceof ConcernsAPersonInterface) {
                yield $name => [$event];
            }
        }
    }
}
