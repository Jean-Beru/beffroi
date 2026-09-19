<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Domain\Credential;

use Heidi\Core\Domain\Credential\PasskeyUserHandle;
use Heidi\Core\Domain\Identity\EmailAddress;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Tests\Fixture\Fixtures;
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
        $handle = PasskeyUserHandle::generate();

        // Then
        static::assertSame(64, strlen($handle->value));
        static::assertNotSame($user->subject->value, $handle->value);
        static::assertNotSame((string) $user->email, $handle->value);
        static::assertFalse($handle->equals(PasskeyUserHandle::generate()));
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
}
