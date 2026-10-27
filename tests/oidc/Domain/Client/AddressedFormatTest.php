<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Client;

use Beffroi\Oidc\Domain\Client\AddressedFormat;
use Beffroi\Oidc\Domain\Client\ResponseFormat;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\LogicException;
use Beffroi\Oidc\Tests\Fixture\ClientEncryption;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Core §3.1.3.7, RFC 7516 §7.1: the shape a client registered for one document, with the key of the
 * client its JWE goes to.
 */
final class AddressedFormatTest extends TestCase
{
    /**
     * A shape that encrypts goes to one key of the client and a shape that does not goes to none, so a key
     * withheld from the one or given to the other is refused when the two are put together.
     *
     * @param array<string, mixed>|null $recipient
     */
    #[Test]
    #[DataProvider('provideMismatches')]
    public function aKeyIsGivenExactlyWhenTheShapeEncrypts(ResponseFormat $format, ?array $recipient): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A document is addressed to one key of the client when its shape encrypts it, and to none when it does not.');

        // When
        new AddressedFormat($format, $recipient);
    }

    /**
     * @return iterable<string, array{ResponseFormat, array<string, mixed>|null}>
     */
    public static function provideMismatches(): iterable
    {
        yield 'a shape that encrypts, and no key' => [ResponseFormat::signed(null, ClientEncryption::registration()), null];
        yield 'a shape that encrypts nothing, and a key' => [ResponseFormat::signed(), self::recipient()];
    }

    /**
     * RFC 7516 §7.1: the JWE of a shape that encrypts goes to the key it was addressed to.
     */
    #[Test]
    public function aShapeThatEncryptsGoesToTheKeyItWasGiven(): void
    {
        // Given
        $key = self::recipient();

        // When
        $addressed = new AddressedFormat(ResponseFormat::signed(null, ClientEncryption::registration()), $key);

        // Then
        static::assertSame($key, $addressed->recipient());
    }

    /**
     * A shape that encrypts nothing goes to no key, and asking it for one is a fault of the caller.
     */
    #[Test]
    public function aShapeThatEncryptsNothingGoesToNoKey(): void
    {
        // Given
        $addressed = new AddressedFormat(ResponseFormat::signed());

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('A document whose shape encrypts nothing is addressed to no key.');

        // When
        $addressed->recipient();
    }

    /**
     * @return array<string, mixed> the public half of the key the client is encrypted to
     */
    private static function recipient(): array
    {
        /** @var array<string, mixed> $key */
        $key = ClientEncryption::privateKey()->toPublic()->all();

        return $key;
    }
}
