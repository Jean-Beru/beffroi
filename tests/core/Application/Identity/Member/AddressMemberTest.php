<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Identity\Member;

use Beffroi\Core\Application\Identity\Member\AddressMember;
use Beffroi\Core\Domain\Identity\Address;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Core §5.1.1, RFC 7396 §2
 */
final class AddressMemberTest extends TestCase
{
    #[Test]
    public function anObjectWritesTheMembersItNamesAndKeepsTheOthers(): void
    {
        // Given
        $alice = self::aliceOf(new Address(streetAddress: '12 rue des Lilas', locality: 'Paris'));

        // When
        new AddressMember()->say($alice, ['locality' => 'Lyon'], Fixtures::now());

        // Then
        static::assertSame(['12 rue des Lilas', 'Lyon'], [$alice->address?->streetAddress, $alice->address?->locality]);
    }

    #[Test]
    public function aMemberSetToNullIsTakenAway(): void
    {
        // Given
        $alice = self::aliceOf(new Address(streetAddress: '12 rue des Lilas', locality: 'Paris'));

        // When
        new AddressMember()->say($alice, ['street_address' => null], Fixtures::now());

        // Then
        static::assertSame([null, 'Paris'], [$alice->address?->streetAddress, $alice->address?->locality]);
    }

    #[Test]
    public function nullTakesTheWholeAddressAway(): void
    {
        // Given
        $alice = self::aliceOf(new Address(locality: 'Paris'));

        // When
        new AddressMember()->say($alice, null, Fixtures::now());

        // Then
        static::assertNull($alice->address);
    }

    #[Test]
    public function anAddressLeftWithNoMemberIsNoAddress(): void
    {
        // Given
        $alice = self::aliceOf(new Address(locality: 'Paris'));

        // When
        new AddressMember()->say($alice, ['locality' => ' '], Fixtures::now());

        // Then
        static::assertNull($alice->address);
    }

    /**
     * @return iterable<string, array{Address|null, mixed}>
     */
    public static function saidAsItIs(): iterable
    {
        yield 'a member as it is' => [new Address(locality: 'Paris'), ['locality' => 'Paris']];
        yield 'an object that names no member' => [new Address(locality: 'Paris'), []];
        yield 'null to a person who has no address' => [null, null];
    }

    #[Test]
    #[DataProvider('saidAsItIs')]
    public function anAddressSaidAsItIsLeavesThePersonUntouched(?Address $address, mixed $said): void
    {
        // Given
        $alice = self::aliceOf($address);

        // When
        new AddressMember()->say($alice, $said, new DateTimeImmutable('2026-09-16T10:00:00+00:00'));

        // Then
        static::assertEquals(Fixtures::now(), $alice->updatedAt);
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function notAnObject(): iterable
    {
        yield 'a list' => [['Lyon']];
        yield 'a string' => ['12 rue des Lilas, Lyon'];
    }

    #[Test]
    #[DataProvider('notAnObject')]
    public function whatIsNotAnObjectIsRefused(mixed $value): void
    {
        // Given
        $alice = self::aliceOf(null);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('"address" is an object of the members of OIDC Core §5.1.1, or null to take it away.');

        // When
        new AddressMember()->say($alice, $value, Fixtures::now());
    }

    #[Test]
    public function aMemberOidcDoesNotDefineIsRefused(): void
    {
        // Given
        $alice = self::aliceOf(null);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An address has no member "planet" (OIDC Core §5.1.1).');

        // When
        new AddressMember()->say($alice, ['planet' => 'Earth'], Fixtures::now());
    }

    #[Test]
    public function theHistoryWritesEachMemberUnderItsOwnName(): void
    {
        // Given
        $alice = self::aliceOf(new Address(locality: 'Paris', country: 'France'));

        // When
        $written = new AddressMember()->of($alice);

        // Then
        static::assertSame(
            [
                'address.formatted' => null,
                'address.street_address' => null,
                'address.locality' => 'Paris',
                'address.region' => null,
                'address.postal_code' => null,
                'address.country' => 'France',
            ],
            $written,
        );
    }

    private static function aliceOf(?Address $address): User
    {
        $alice = Fixtures::user();
        $alice->changeAddress($address, Fixtures::now());

        return $alice;
    }
}
