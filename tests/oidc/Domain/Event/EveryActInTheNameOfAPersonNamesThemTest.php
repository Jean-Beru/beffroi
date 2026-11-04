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

final class EveryActInTheNameOfAPersonNamesThemTest extends TestCase
{
    private const array NAMES_NOBODY = [
        ClientAuthenticationFailed::class => 'a request refused before any client was authenticated names neither a client nor a person (RFC 6749 §5.2)',
        PushedRequestRefused::class => 'a reference refused at the authorization endpoint says what was refused, and nobody had been asked anything yet (RFC 9126 §4)',
        RegisteredClientDeleted::class => 'a client taken out of the register is an act of whoever registered it, in the name of no person this provider serves (RFC 7592 §2.3)',
    ];

    /**
     * OIDC Core §8.1
     */
    #[Test]
    #[DataProvider('actsInTheNameOfAPerson')]
    public function anActInTheNameOfAPersonNamesThemByTheSubjectOfTheirAccount(ConcernsAPersonInterface $event): void
    {
        // When / Then
        static::assertSame('alice-subject', $event->subject()?->value, $event->name());
    }

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
