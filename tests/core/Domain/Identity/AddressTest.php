<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Identity;

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
}
