<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Domain\Identity;

use Heidi\Core\Domain\Identity\Address;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class AddressTest extends TestCase
{
    #[Test]
    public function anAddressWithNoFieldIsEmpty(): void
    {
        static::assertTrue(new Address()->isEmpty());
    }

    /**
     * OIDC Core §5.1.1: every member of the address claim is optional; any one of them makes an address.
     */
    #[Test]
    #[DataProvider('provideSingleFieldAddresses')]
    public function anySingleFieldMakesAnAddress(Address $address): void
    {
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
}
