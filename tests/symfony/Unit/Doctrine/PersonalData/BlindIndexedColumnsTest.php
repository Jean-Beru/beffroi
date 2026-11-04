<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Doctrine\PersonalData;

use function array_unique;
use function array_values;
use App\Doctrine\PersonalData\BlindIndexedColumns;
use App\Doctrine\PersonalData\EncryptedColumnTypes;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\KeyManagement\BlindIndexInterface;
use Symfony\Component\KeyManagement\Test\InMemoryDataKeyStore;

/**
 * Decision 0011
 */
final class BlindIndexedColumnsTest extends TestCase
{
    #[Test]
    public function aUsernameDifferingOnlyByItsCaseIsADifferentTag(): void
    {
        // Given
        $index = self::index('username');

        // When / Then
        static::assertNotSame($index->of('alice'), $index->of('Alice'));
    }

    /**
     * RFC 5321 §2.4
     */
    #[Test]
    public function anAddressDifferingOnlyByTheCaseOfItsDomainIsTheSameTag(): void
    {
        // Given
        $index = self::index('email');

        // When / Then
        static::assertSame($index->of('Ada@Example.org'), $index->of('Ada@EXAMPLE.ORG'));
    }

    #[Test]
    public function anAddressDifferingOnlyByTheCaseOfItsLocalPartIsTheSameTag(): void
    {
        // Given
        $index = self::index('email');

        // When / Then
        static::assertSame($index->of('Ada@example.org'), $index->of('ada@example.org'));
    }

    #[Test]
    public function anAddressDifferingByItsLocalPartIsADifferentTag(): void
    {
        // Given
        $index = self::index('email');

        // When / Then
        static::assertNotSame($index->of('ada@example.org'), $index->of('grace@example.org'));
    }

    /**
     * Decision 0011
     */
    #[Test]
    public function theTwoColumnsOfOneTenantDoNotShareTheirTagForOneValue(): void
    {
        // Given
        $store = new InMemoryDataKeyStore();
        $reference = $store->current('acme.blind_index')->reference;

        // When
        $username = BlindIndexedColumns::of(User::class, 'username')->index($store, $reference);
        $email = BlindIndexedColumns::of(User::class, 'email')->index($store, $reference);

        // Then
        static::assertNotSame($username->of('ada@example.org'), $email->of('ada@example.org'));
    }

    #[Test]
    public function noTwoColumnsNameTheirIndexAlike(): void
    {
        // When
        $tags = BlindIndexedColumns::tags();

        // Then
        static::assertSame($tags, array_values(array_unique($tags)));
    }

    #[Test]
    public function aColumnNoIndexIsDeclaredOnIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('No blind index is declared on "Beffroi\Core\Domain\Identity\User::$phoneNumber", so nothing can be searched by it.');

        // When
        BlindIndexedColumns::of(User::class, 'phoneNumber');
    }

    /**
     * Decision 0018
     */
    #[Test]
    public function theScopeOfTheIndexKeyIsNoFamilyOfColumns(): void
    {
        // When / Then
        static::assertArrayNotHasKey(BlindIndexedColumns::SCOPE, EncryptedColumnTypes::FAMILIES);
    }

    private static function index(string $property): BlindIndexInterface
    {
        $store = new InMemoryDataKeyStore();

        return BlindIndexedColumns::of(User::class, $property)->index($store, $store->current('acme.blind_index')->reference);
    }
}
