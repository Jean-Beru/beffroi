<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Identity;

use function str_repeat;
use function sprintf;
use Beffroi\Core\Domain\Identity\Address;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class AddressTest extends TestCase
{
    #[Test]
    public function anAddressWithNoFieldIsEmpty(): void
    {
        // When / Then
        static::assertTrue(new Address()->isEmpty());
    }

    /**
     * OIDC Core §5.1.1
     */
    #[Test]
    #[DataProvider('provideSingleFieldAddresses')]
    public function anySingleFieldMakesAnAddress(Address $address): void
    {
        // When / Then
        static::assertFalse($address->isEmpty());
    }

    /**
     * @return iterable<string, array{Address}>
     */
    public static function provideSingleFieldAddresses(): iterable
    {
        yield 'formatted' => [new Address(formatted: "1 rue de la Paix\n75002 Paris")];
        yield 'street' => [new Address(streetAddress: '1 rue de la Paix')];
        yield 'locality' => [new Address(locality: 'Paris')];
        yield 'region' => [new Address(region: 'Île-de-France')];
        yield 'postal code' => [new Address(postalCode: '75002')];
        yield 'country' => [new Address(country: 'FR')];
    }

    /**
     * OIDC Core §5.1.1
     *
     * @param array<string, string|null> $document
     */
    #[Test]
    #[DataProvider('provideDocuments')]
    public function itWritesTheDocumentAColumnHoldsItAs(Address $address, array $document): void
    {
        // When / Then
        static::assertSame($document, $address->toDocument());
    }

    /**
     * @param array<string, string|null> $document
     */
    #[Test]
    #[DataProvider('provideDocuments')]
    public function itComesBackOutOfItsDocument(Address $address, array $document): void
    {
        // When / Then
        static::assertEquals($address, Address::fromDocument($document));
    }

    /**
     * @return iterable<string, array{Address, array<string, string|null>}>
     */
    public static function provideDocuments(): iterable
    {
        yield 'an address' => [
            new Address('1 rue de la Paix, 75002 Paris', '1 rue de la Paix', 'Paris', null, '75002', 'FR'),
            [
                'formatted' => '1 rue de la Paix, 75002 Paris',
                'street_address' => '1 rue de la Paix',
                'locality' => 'Paris',
                'region' => null,
                'postal_code' => '75002',
                'country' => 'FR',
            ],
        ];
        yield 'an address with no field' => [
            new Address(),
            [
                'formatted' => null,
                'street_address' => null,
                'locality' => null,
                'region' => null,
                'postal_code' => null,
                'country' => null,
            ],
        ];
    }

    /**
     * @param array<array-key, mixed> $document
     */
    #[Test]
    #[DataProvider('provideDocumentsThatAreNotAnAddress')]
    public function aDocumentThatIsNotAnAddressIsRefused(array $document, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        Address::fromDocument($document);
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>, string}>
     */
    public static function provideDocumentsThatAreNotAnAddress(): iterable
    {
        yield 'a numeric postal code' => [
            [
                'postal_code' => 75002,
            ],
            'The member "postal_code" must be a string or absent.',
        ];
        yield 'a formatted address that is an object' => [
            [
                'formatted' => [
                    'line' => '1 rue de la Paix',
                ],
            ],
            'The member "formatted" must be a string or absent.',
        ];
    }

    /**
     * OIDC Core §5.1.1
     */
    #[Test]
    #[DataProvider('provideMembersThatAreNotPlainText')]
    public function aMemberThatIsNotPlainTextIsRefused(string $member, string $value, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        new Address(...[$member => $value]);
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function provideMembersThatAreNotPlainText(): iterable
    {
        $lines = 'The %s of an address must be plain text of at most 1024 characters, its lines separated by line feeds, with no other control, format or separator character.';
        $line = 'The %s of an address must be plain text of at most 255 characters, with no control, format or line separator character.';
        $escape = "1 Main Street\e[2K\e[1A\e[2KNothing to see";
        yield 'an escape sequence in the formatted address' => ['formatted', $escape, sprintf($lines, 'formatted')];
        yield 'an escape sequence in the street' => ['streetAddress', $escape, sprintf($lines, 'street_address')];
        yield 'an escape sequence in the locality' => ['locality', $escape, sprintf($line, 'locality')];
        yield 'an escape sequence in the region' => ['region', $escape, sprintf($line, 'region')];
        yield 'an escape sequence in the postal code' => ['postalCode', $escape, sprintf($line, 'postal_code')];
        yield 'an escape sequence in the country' => ['country', $escape, sprintf($line, 'country')];
        yield 'a carriage return alone in the street' => ['streetAddress', "1 Main Street\rFlat 2", sprintf($lines, 'street_address')];
        yield 'a line feed in the locality' => ['locality', "Oxford\nYour account is locked", sprintf($line, 'locality')];
        yield 'a right-to-left override in the country' => ['country', "United Kingdom\u{202E}", sprintf($line, 'country')];
        yield 'a street longer than its lines may be' => ['streetAddress', str_repeat('a', 1025), sprintf($lines, 'street_address')];
        yield 'a locality longer than a line may be' => ['locality', str_repeat('a', 256), sprintf($line, 'locality')];
    }

    /**
     * OIDC Core §5.1.1
     */
    #[Test]
    #[DataProvider('provideAddressesOnSeveralLines')]
    public function theFormattedAddressAndTheStreetHoldSeveralLines(string $member, string $claim, string $value): void
    {
        // When
        $address = new Address(...[$member => $value]);

        // Then
        static::assertSame($value, $address->toDocument()[$claim]);
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function provideAddressesOnSeveralLines(): iterable
    {
        yield 'a formatted address separated by line feeds' => ['formatted', 'formatted', "1 Wonderland Road\nOxford OX1 1AA\nUnited Kingdom"];
        yield 'a street separated by a carriage return and a line feed' => ['streetAddress', 'street_address', "1 Wonderland Road\r\nFlat 2"];
    }
}
