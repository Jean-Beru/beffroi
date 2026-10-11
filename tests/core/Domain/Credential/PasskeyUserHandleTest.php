<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Credential;

use Beffroi\Core\Domain\Credential\PasskeyUserHandle;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use function strlen;

/**
 * WebAuthn Level 3 §14.6.1: the user handle carries no personal information, 64 random bytes.
 */
final class PasskeyUserHandleTest extends TestCase
{
    #[Test]
    public function aGeneratedHandleIs64RandomBytesNeitherTheSubjectNorTheEmail(): void
    {
        // Given
        $user = Fixtures::user();
        $user->changeEmail(new EmailAddress('alice@acme.example'), true, Fixtures::now());

        // When
        $handle = Fixtures::userHandle();

        // Then
        static::assertSame(64, strlen($handle->value));
        static::assertNotSame($user->subject->value, $handle->value);
        static::assertNotSame((string) $user->email, $handle->value);
        static::assertFalse($handle->equals(Fixtures::userHandle()));
    }

    #[Test]
    public function twoHandlesOfTheSameBytesAreEqual(): void
    {
        // Given
        $bytes = str_repeat('h', 64);

        // When / Then
        static::assertTrue(new PasskeyUserHandle($bytes)->equals(new PasskeyUserHandle($bytes)));
    }

    #[Test]
    #[DataProvider('provideWrongLengths')]
    public function aHandleOfAnotherLengthIsRefused(string $value): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A passkey user handle is 64 bytes long.');

        // When
        new PasskeyUserHandle($value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWrongLengths(): iterable
    {
        yield 'empty' => [''];
        yield 'a subject' => ['alice-subject'];
        yield '63 bytes' => [str_repeat('h', 63)];
        yield '65 bytes' => [str_repeat('h', 65)];
    }

    /**
     * WebAuthn Level 3 §5.4.3: the sixty-four octets as a column holds them, base64url without padding.
     */
    #[Test]
    public function itWritesTheValueAColumnHoldsItAs(): void
    {
        // When / Then
        static::assertSame(str_repeat('_', 85) . 'w', new PasskeyUserHandle(str_repeat("\xff", 64))->toDocument());
    }

    #[Test]
    public function itComesBackOutOfItsValue(): void
    {
        // Given
        $handle = new PasskeyUserHandle(str_repeat("\xff", 64));

        // When / Then
        static::assertEquals($handle, PasskeyUserHandle::fromDocument($handle->toDocument()));
    }

    #[Test]
    public function aValueThatIsNotBase64UrlIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A user handle is base64url.');

        // When
        PasskeyUserHandle::fromDocument(str_repeat('*', 86));
    }

    #[Test]
    public function aValueOfTheWrongLengthIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A passkey user handle is 64 bytes long.');

        // When
        PasskeyUserHandle::fromDocument(str_repeat('a', 84));
    }
}
