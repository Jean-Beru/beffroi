<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Resource;

use function array_map;
use Beffroi\Oidc\Domain\Resource\ResourceIndicator;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function iterator_to_array;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 8707 §2
 */
final class ResourceIndicatorsTest extends TestCase
{
    private const string CALENDAR = 'https://cal.example.com/';

    private const string CONTACTS = 'https://contacts.example.com/';

    #[Test]
    public function aSetHoldsAtLeastOneResource(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A set of resources holds at least one resource (RFC 8707 section 2).');

        // When
        new ResourceIndicators([]);
    }

    /**
     * RFC 8707 §2
     */
    #[Test]
    public function aResourceNamedTwiceCountsOnce(): void
    {
        // When
        $resources = ResourceIndicators::of([self::CONTACTS, self::CALENDAR, self::CONTACTS]);

        // Then
        static::assertSame([self::CONTACTS, self::CALENDAR], $resources->values());
    }

    #[Test]
    public function aSetHoldsWhatItWasGiven(): void
    {
        // Given
        $resources = ResourceIndicators::of([self::CALENDAR]);

        // When / Then
        static::assertTrue($resources->has(new ResourceIndicator(self::CALENDAR)));
    }

    #[Test]
    public function aSetDoesNotHoldWhatItWasNotGiven(): void
    {
        // Given
        $resources = ResourceIndicators::of([self::CALENDAR]);

        // When / Then
        static::assertFalse($resources->has(new ResourceIndicator(self::CONTACTS)));
    }

    /**
     * RFC 8707 §2.2
     *
     * @param list<string> $held
     * @param list<string> $asked
     */
    #[Test]
    #[DataProvider('provideCoverage')]
    public function aSetCoversAnotherWhenItHoldsEveryResourceOfIt(array $held, array $asked, bool $covers): void
    {
        // Given
        $resources = ResourceIndicators::of($held);

        // When / Then
        static::assertSame($covers, $resources->covers(ResourceIndicators::of($asked)));
    }

    /**
     * @return iterable<string, array{list<string>, list<string>, bool}>
     */
    public static function provideCoverage(): iterable
    {
        yield 'the same set' => [[self::CALENDAR], [self::CALENDAR], true];
        yield 'a subset' => [[self::CALENDAR, self::CONTACTS], [self::CONTACTS], true];
        yield 'another resource' => [[self::CALENDAR], [self::CONTACTS], false];
        yield 'one more resource' => [[self::CALENDAR], [self::CALENDAR, self::CONTACTS], false];
    }

    #[Test]
    public function twoSetsAreEqualWhenEachCoversTheOther(): void
    {
        // Given
        $resources = ResourceIndicators::of([self::CALENDAR, self::CONTACTS]);

        // When / Then
        static::assertTrue($resources->equals(ResourceIndicators::of([self::CONTACTS, self::CALENDAR])));
    }

    #[Test]
    public function aSetIsNotEqualToOneItMerelyCovers(): void
    {
        // Given
        $resources = ResourceIndicators::of([self::CALENDAR, self::CONTACTS]);

        // When / Then
        static::assertFalse($resources->equals(ResourceIndicators::of([self::CALENDAR])));
    }

    #[Test]
    public function aSetCountsWhatItHolds(): void
    {
        // When / Then
        static::assertCount(2, ResourceIndicators::of([self::CALENDAR, self::CONTACTS]));
    }

    #[Test]
    public function aSetIsWalkedOverAsASet(): void
    {
        // Given
        $resources = ResourceIndicators::of([self::CALENDAR, self::CONTACTS]);

        // When
        $walked = array_map(
            static fn (ResourceIndicator $resource): string => $resource->value,
            iterator_to_array($resources),
        );

        // Then
        static::assertSame([self::CALENDAR, self::CONTACTS], $walked);
    }

    #[Test]
    public function itRefusesAValueThatIsNotAnAbsoluteUri(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('is not an absolute URI');

        // When
        ResourceIndicators::of([self::CALENDAR, 'cal.example.com']);
    }

    /**
     * RFC 8707 §2
     */
    #[Test]
    public function itWritesTheValueAColumnHoldsItAs(): void
    {
        // When / Then
        static::assertSame(
            self::CALENDAR . ' ' . self::CONTACTS,
            ResourceIndicators::of([self::CALENDAR, self::CONTACTS])->toDocument(),
        );
    }

    #[Test]
    public function itComesBackOutOfItsValue(): void
    {
        // Given
        $resources = ResourceIndicators::of([self::CALENDAR, self::CONTACTS]);

        // When / Then
        static::assertEquals($resources, ResourceIndicators::fromDocument($resources->toDocument()));
    }

    #[Test]
    public function aValueHoldingSomethingThatIsNotAResourceIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('is not an absolute URI');

        // When
        ResourceIndicators::fromDocument(self::CALENDAR . ' cal.example.com');
    }
}
