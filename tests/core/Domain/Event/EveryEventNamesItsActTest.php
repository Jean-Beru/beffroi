<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Event;

use Beffroi\Core\Domain\Event\DomainEventInterface;
use function array_unique;
use function count;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_match;

/**
 * Issue #454: an act of the journal is named by the event that announces it, and the interface is what
 * makes that so. These are the events of the core; the module has the same test for its own, and both read
 * the list its walk through a queue already keeps, so an event added to either package is covered by
 * existing.
 */
final class EveryEventNamesItsActTest extends TestCase
{
    /**
     * A name a row of a journal carries for years: lowercase words, the thing before the dot and what
     * happened to it after, as "user.authenticated". Nothing a reader has to decode, and nothing that
     * would have to be rewritten because a class moved.
     */
    #[Test]
    #[DataProvider('events')]
    public function anEventNamesItsAct(DomainEventInterface $event): void
    {
        // When / Then
        static::assertSame(1, preg_match('/^[a-z][a-z_]*\.[a-z][a-z_]*$/', $event->name()), $event->name());
    }

    /**
     * Two kinds of event under one name would be two things a reader of the journal cannot tell apart. The
     * walk yields one kind more than once, a shape of it per case, which is why the names are counted
     * against the kinds and not against the cases.
     */
    #[Test]
    public function noTwoKindsOfEventShareAName(): void
    {
        // Given
        $names = [];
        foreach (self::events() as $case) {
            $names[$case[0]::class] = $case[0]->name();
        }

        // When / Then
        static::assertCount(count($names), array_unique($names));
    }

    /**
     * @return iterable<string, array{DomainEventInterface}>
     */
    public static function events(): iterable
    {
        return EventsLeaveTheProcessTest::events();
    }
}
