<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Configuration;

use ArrayIterator;
use App\Configuration\RoleSwitch;
use App\Configuration\SwitchedServices;
use Generator;
use function iterator_to_array;
use IteratorAggregate;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use stdClass;

/**
 * Decision 0030
 */
final class SwitchedServicesTest extends TestCase
{
    #[Test]
    public function aRoleThatIsOnBringsItsServicesAfterThoseTheTagWires(): void
    {
        // Given
        $wired = [new stdClass(), new stdClass()];
        $brought = new stdClass();

        // When
        $services = iterator_to_array(new SwitchedServices($wired, new RoleSwitch(true), new ArrayIterator([$brought])));

        // Then
        static::assertSame([$wired[0], $wired[1], $brought], $services);
    }

    #[Test]
    public function aRoleThatIsOffListsWhatTheTagWiresAlone(): void
    {
        // Given
        $wired = [new stdClass()];

        // When
        $services = iterator_to_array(new SwitchedServices($wired, new RoleSwitch(false), new ArrayIterator([new stdClass()])));

        // Then
        static::assertSame($wired, $services);
    }

    #[Test]
    public function aRoleThatIsOffBuildsNothingOfWhatItWouldBring(): void
    {
        // Given
        $services = new SwitchedServices(
            [],
            new RoleSwitch(false),
            /** @implements IteratorAggregate<int, stdClass> */
            new class implements IteratorAggregate {
                /**
                 * @return Generator<int, stdClass>
                 */
                public function getIterator(): Generator
                {
                    TestCase::fail('A role that is off builds nothing of what it would bring.');
                }
            },
        );

        // When
        $listed = iterator_to_array($services);

        // Then
        static::assertSame([], $listed);
    }

    #[Test]
    public function theListIsTheSameEveryTimeItIsRead(): void
    {
        // Given
        $services = new SwitchedServices([new stdClass()], new RoleSwitch(true), new ArrayIterator([new stdClass()]));
        $first = iterator_to_array($services);

        // When
        $second = iterator_to_array($services);

        // Then
        static::assertSame($first, $second);
    }
}
