<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Claims;

use Beffroi\Oidc\Domain\Claims\ClaimNames;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function iterator_to_array;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Core §5.1, §5.5: claims by their names, each once, as a request asks for them one by one, as a scope
 * stands for them and as a consent holds them.
 */
final class ClaimNamesTest extends TestCase
{
    #[Test]
    public function itHoldsEachNameOnceInTheOrderItWasFirstSeen(): void
    {
        // When
        $claims = new ClaimNames(['email', 'name', 'email']);

        // Then
        static::assertSame(['email', 'name'], $claims->all);
        static::assertCount(2, $claims);
        static::assertSame(['email', 'name'], iterator_to_array($claims));
    }

    /**
     * A set that holds no name is a set too: what a consent given for its scopes alone holds by name.
     */
    #[Test]
    public function aSetMayHoldNoName(): void
    {
        // When
        $claims = new ClaimNames();

        // Then
        static::assertTrue($claims->isEmpty());
        static::assertSame([], $claims->all);
    }

    #[Test]
    public function itRefusesAClaimWithoutAName(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A claim has a name (OIDC Core section 5.1).');

        // When
        new ClaimNames(['email', '']);
    }

    /**
     * @param list<string> $other
     */
    #[Test]
    #[DataProvider('provideCoverings')]
    public function itCoversASetWhoseEveryNameItHolds(array $other, bool $covered): void
    {
        // Given
        $claims = new ClaimNames(['email', 'name']);

        // When / Then
        static::assertSame($covered, $claims->covers(new ClaimNames($other)));
    }

    /**
     * @return iterable<string, array{list<string>, bool}>
     */
    public static function provideCoverings(): iterable
    {
        yield 'a set that holds no name' => [[], true];
        yield 'one of its names' => [['name'], true];
        yield 'all its names in another order' => [['name', 'email'], true];
        yield 'a name it does not hold' => [['phone_number'], false];
        yield 'one of its names and another' => [['email', 'phone_number'], false];
    }

    #[Test]
    public function withAnotherSetItHoldsTheNamesOfBothItsOwnFirst(): void
    {
        // When
        $claims = new ClaimNames(['email', 'name'])->with(new ClaimNames(['phone_number', 'email']));

        // Then
        static::assertSame(['email', 'name', 'phone_number'], $claims->all);
    }

    #[Test]
    public function withinAnotherSetItHoldsTheNamesBothHoldInItsOwnOrder(): void
    {
        // When
        $claims = new ClaimNames(['email', 'name', 'phone_number'])->within(new ClaimNames(['phone_number', 'email', 'address']));

        // Then
        static::assertSame(['email', 'phone_number'], $claims->all);
    }

    #[Test]
    public function withoutAnotherSetItHoldsTheNamesTheOtherDoesNotHold(): void
    {
        // When
        $claims = new ClaimNames(['email', 'name', 'phone_number'])->without(new ClaimNames(['name', 'address']));

        // Then
        static::assertSame(['email', 'phone_number'], $claims->all);
    }

    /**
     * @param list<string> $names
     */
    #[Test]
    #[DataProvider('provideSets')]
    public function itWritesTheDocumentAColumnHoldsItAs(array $names): void
    {
        // When / Then
        static::assertSame($names, new ClaimNames($names)->toDocument());
    }

    /**
     * @param list<string> $names
     */
    #[Test]
    #[DataProvider('provideSets')]
    public function itComesBackOutOfItsDocument(array $names): void
    {
        // When / Then
        static::assertSame($names, ClaimNames::fromDocument($names)->all);
    }

    /**
     * @return iterable<string, array{list<string>}>
     */
    public static function provideSets(): iterable
    {
        yield 'no name' => [[]];
        yield 'one name' => [['email']];
        yield 'two names' => [['email', 'phone_number']];
    }

    /**
     * A row edited by hand is refused where it is read rather than coerced into a set it never was.
     *
     * @param array<array-key, mixed> $document
     */
    #[Test]
    #[DataProvider('provideDocumentsThatAreNoSet')]
    public function itRefusesADocumentThatIsNoSetOfNames(array $document, string $reason): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($reason);

        // When
        ClaimNames::fromDocument($document);
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>, string}>
     */
    public static function provideDocumentsThatAreNoSet(): iterable
    {
        yield 'an object' => [['email' => true], 'A set of claims is a list of their names (OIDC Core section 5.1).'];
        yield 'a number' => [['email', 4], 'A set of claims holds their names (OIDC Core section 5.1).'];
        yield 'an empty name' => [[''], 'A claim has a name (OIDC Core section 5.1).'];
    }
}
