<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Event;

use Beffroi\Core\Domain\Event\DomainEventInterface;
use function array_unique;
use function count;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_match;

final class EveryEventNamesItsActTest extends TestCase
{
    #[Test]
    #[DataProvider('events')]
    public function anEventNamesItsAct(DomainEventInterface $event): void
    {
        // When / Then
        static::assertSame(1, preg_match('/^[a-z][a-z_]*\.[a-z][a-z_]*$/', $event->name()), $event->name());
    }

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
