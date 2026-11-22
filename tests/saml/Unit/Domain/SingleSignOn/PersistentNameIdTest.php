<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\SingleSignOn;

use Beffroi\Core\Domain\Encoding\Base64Url;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\SingleSignOn\PersistentNameId;
use function hash;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * S-13, Core §8.3.7
 */
final class PersistentNameIdTest extends TestCase
{
    private const string SERVICE_PROVIDER = 'https://sp.example.org/saml';

    private const string SALT = 'the salt of the tenant';

    /**
     * S-13
     */
    #[Test]
    public function itIsTheHashOfTheServiceProviderTheSubjectAndTheSalt(): void
    {
        // When / Then
        static::assertSame(
            Base64Url::encode(hash('sha256', self::SERVICE_PROVIDER . "\0alice-subject\0" . self::SALT . "\0", true)),
            PersistentNameId::derive(self::SERVICE_PROVIDER, new Subject('alice-subject'), self::SALT)->value,
        );
    }

    /**
     * S-13
     */
    #[Test]
    public function itIsTheSameAtEveryDerivation(): void
    {
        // When / Then
        static::assertEquals(
            PersistentNameId::derive(self::SERVICE_PROVIDER, new Subject('alice-subject'), self::SALT),
            PersistentNameId::derive(self::SERVICE_PROVIDER, new Subject('alice-subject'), self::SALT),
        );
    }

    /**
     * S-13
     */
    #[Test]
    public function anotherServiceProviderGetsAnotherIdentifier(): void
    {
        // When / Then
        static::assertNotSame(
            PersistentNameId::derive(self::SERVICE_PROVIDER, new Subject('alice-subject'), self::SALT)->value,
            PersistentNameId::derive('https://other.example.org/saml', new Subject('alice-subject'), self::SALT)->value,
        );
    }

    /**
     * S-13
     */
    #[Test]
    public function anotherSaltGivesAnotherIdentifier(): void
    {
        // When / Then
        static::assertNotSame(
            PersistentNameId::derive(self::SERVICE_PROVIDER, new Subject('alice-subject'), self::SALT)->value,
            PersistentNameId::derive(self::SERVICE_PROVIDER, new Subject('alice-subject'), 'another salt')->value,
        );
    }

    /**
     * Core §8.3.7
     */
    #[Test]
    public function aValueOverTheLengthOfTheFormatIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A persistent identifier is 1 to 256 characters long (Core section 8.3.7).');

        // When
        new PersistentNameId(str_repeat('a', 257));
    }

    /**
     * Core §8.3.7
     */
    #[Test]
    public function aValueOfTheLengthOfTheFormatIsKept(): void
    {
        // When / Then
        static::assertSame(str_repeat('a', 256), new PersistentNameId(str_repeat('a', 256))->value);
    }

    /**
     * Core §8.3.7
     */
    #[Test]
    public function anEmptyValueIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A persistent identifier is 1 to 256 characters long (Core section 8.3.7).');

        // When
        new PersistentNameId('');
    }
}
