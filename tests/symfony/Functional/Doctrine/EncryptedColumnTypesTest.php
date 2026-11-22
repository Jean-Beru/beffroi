<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use function array_diff;
use function array_keys;
use function array_values;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Types\TextType;
use App\Doctrine\PersonalData\EncryptedColumnTypes;
use App\Doctrine\PersonalData\TenantScopedEncrypter;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\KeyManagement\Bridge\DoctrineDbal\EncryptedType;
use Symfony\Component\KeyManagement\Exception\DecryptionFailedException;

final class EncryptedColumnTypesTest extends DatabaseTestCase
{
    private const string TABLE = 'test_sealed_column';

    /**
     * Decision 0018
     */
    #[Test]
    public function theProviderDeclaresOneTypePerFamilyAndPerTypeThatFamilySeals(): void
    {
        // When / Then
        static::assertCount(16, EncryptedColumnTypes::FAMILIES);
        static::assertCount(27, EncryptedColumnTypes::declarations());
    }

    #[Test]
    public function everyTypeTheProviderDeclaresIsNamedByAMapping(): void
    {
        // Given
        $named = [];
        foreach (self::entityManager()->getMetadataFactory()->getAllMetadata() as $metadata) {
            foreach ($metadata->fieldMappings as $mapping) {
                $named[$mapping->type] = true;
            }
        }

        // When
        $unnamed = array_values(array_diff(EncryptedColumnTypes::names(), array_keys($named)));

        // Then
        static::assertSame([], $unnamed, 'A type is declared that no mapping names.');
    }

    #[Test]
    public function everyDeclaredTypeIsRegisteredOnceTheKernelHasBooted(): void
    {
        // Given
        $types = self::typesOfTheConnection();

        // When / Then
        foreach (EncryptedColumnTypes::names() as $name) {
            static::assertTrue($types->has($name), $name . ' is declared by the provider and not registered.');
            static::assertInstanceOf(EncryptedType::class, $types->get($name));
        }
    }

    #[Test]
    public function aValueSealedByAnEncryptedTypeIsReadBackAsTheDomainObjectItWas(): void
    {
        // Given
        $type = self::typesOfTheConnection()->get(EncryptedColumnTypes::name('user', 'beffroi_email_address'));
        $platform = self::connection()->getDatabasePlatform();
        $address = new EmailAddress('alice@example.com');

        // When
        $sealed = $type->convertToDatabaseValue($address, $platform);
        $read = $type->convertToPHPValue($sealed, $platform);

        // Then
        static::assertInstanceOf(EmailAddress::class, $read);
        static::assertSame($address->value, $read->value);
    }

    /**
     * Decision 0011
     */
    #[Test]
    public function theBytesTheColumnHoldsAreNotThePlaintext(): void
    {
        // Given
        $connection = self::connection();
        $connection->executeStatement('CREATE TABLE ' . self::TABLE . ' (id INTEGER PRIMARY KEY, value BLOB)');
        $name = EncryptedColumnTypes::name('user', 'beffroi_email_address');

        // When
        $connection->insert(
            self::TABLE,
            [
                'id' => 1,
                'value' => new EmailAddress('alice@example.com'),
            ],
            [
                'value' => $name,
            ],
        );
        $stored = self::storedBytes($connection);

        // Then
        static::assertStringNotContainsString('alice@example.com', $stored, 'The column holds the address in the clear.');
        $read = self::typesOfTheConnection()->get($name)->convertToPHPValue($stored, $connection->getDatabasePlatform());
        static::assertInstanceOf(EmailAddress::class, $read);
        static::assertSame('alice@example.com', $read->value);
    }

    /**
     * Decision 0018
     */
    #[Test]
    #[DataProvider('provideColumnsOfAnotherFamilyOrType')]
    public function aValueCopiedIntoAColumnOfAnotherFamilyOrTypeDoesNotOpenThere(string $sealedBy, string $value, string $readBy): void
    {
        // Given
        $platform = self::connection()->getDatabasePlatform();
        $copied = self::typesOfTheConnection()->get($sealedBy)->convertToDatabaseValue($value, $platform);

        // Then
        $this->expectException(DecryptionFailedException::class);

        // When
        self::typesOfTheConnection()->get($readBy)->convertToPHPValue($copied, $platform);
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function provideColumnsOfAnotherFamilyOrType(): iterable
    {
        yield 'the subject of a linked identity into the username of a user' => [
            EncryptedColumnTypes::name('linked_identity', 'string'),
            '110169484474386276334',
            EncryptedColumnTypes::name('user', 'string'),
        ];
        yield 'the username of a user into the email of a user' => [
            EncryptedColumnTypes::name('user', 'string'),
            'alice',
            EncryptedColumnTypes::name('user', 'beffroi_email_address'),
        ];
    }

    /**
     * Decision 0018
     */
    #[Test]
    public function aSealedValueIsBoundToTheNameOfTheTypeItDecoratesAndNotToItsClass(): void
    {
        // Given
        $platform = self::connection()->getDatabasePlatform();
        $sealed = self::typesOfTheConnection()->get(EncryptedColumnTypes::name('user', 'string'))->convertToDatabaseValue('alice', $platform);
        $sameNameOtherClass = new EncryptedType(
            new TextType(),
            self::service('beffroi.personal_data.encrypter', TenantScopedEncrypter::class),
            'user',
            'string',
        );

        // When
        $read = $sameNameOtherClass->convertToPHPValue($sealed, $platform);

        // Then
        static::assertSame('alice', $read);
    }

    #[Test]
    public function aKernelBootedASecondTimeRegistersTheSameNamesAgain(): void
    {
        // Given
        $name = EncryptedColumnTypes::name('user', 'beffroi_email_address');
        $before = self::typesOfTheConnection()->get($name);

        // When
        self::ensureKernelShutdown();
        self::bootKernel();

        // Then
        $after = self::typesOfTheConnection()->get($name);
        static::assertInstanceOf(EncryptedType::class, $after);
        static::assertNotSame(
            $before,
            $after,
            'The second kernel left the type of the first one in place, pointing at an encrypter nothing else uses any more.',
        );
    }

    #[Test]
    #[DataProvider('provideNames')]
    public function theNameOfATypeIsTheFamilyAndTheTypeItSeals(string $family, string $type, string $expected): void
    {
        // When / Then
        static::assertSame($expected, EncryptedColumnTypes::name($family, $type));
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function provideNames(): iterable
    {
        yield 'a type of the platform' => ['user', 'string', 'beffroi_encrypted_user_string'];
        yield 'a type of the provider, whose prefix is dropped' => ['user', 'beffroi_address', 'beffroi_encrypted_user_address'];
        yield 'a family whose name is a sentence' => [
            'backchannel_authentication_request',
            'beffroi_request_context',
            'beffroi_encrypted_backchannel_authentication_request_request_context',
        ];
    }

    #[Test]
    public function aTypeAFamilyDoesNotSealIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The family "interaction" seals no column of type "beffroi_address". The families are user, linked_identity, passkey_credential, push_subscription, authentication_session, interaction, pushed_authorization_request, device_authorization_request, backchannel_authentication_request, client, journal, personal_archive, claim_change, disclosure, saml_service_provider, saml_upstream_identity_provider.');

        // When
        EncryptedColumnTypes::name('interaction', 'beffroi_address');
    }

    #[Test]
    public function everySealingTypeSaysWhichFamilyItSealsUnder(): void
    {
        // When
        $families = EncryptedColumnTypes::familyByType();

        // Then
        static::assertSame(EncryptedColumnTypes::names(), array_keys($families));
        static::assertSame([], array_diff($families, EncryptedColumnTypes::families()));
    }

    private static function connection(): Connection
    {
        return self::entityManager()->getConnection();
    }

    private static function storedBytes(Connection $connection): string
    {
        $stored = $connection->fetchOne('SELECT value FROM ' . self::TABLE . ' WHERE id = 1');
        static::assertIsString($stored);

        return $stored;
    }
}
