<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Domain\Credential;

use Heidi\Core\Domain\Credential\TotpSecret;
use Heidi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use function strlen;

/**
 * RFC 4226 §4: the shared secret of a TOTP, 160 bits drawn at random, at least 128.
 */
final class TotpSecretTest extends TestCase
{
    #[Test]
    public function aGeneratedSecretIsTwentyRandomBytes(): void
    {
        // When
        $first = TotpSecret::generate();
        $second = TotpSecret::generate();

        // Then
        static::assertSame(TotpSecret::LENGTH, strlen($first->bytes));
        static::assertSame(20, strlen($second->bytes));
        static::assertNotSame($first->bytes, $second->bytes);
    }

    #[Test]
    public function aSecretOfSixteenBytesIsTheShortestAccepted(): void
    {
        // When / Then
        static::assertSame(16, strlen(new TotpSecret(str_repeat('a', 16))->bytes));
    }

    #[Test]
    public function aShorterSecretIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A TOTP secret is at least 16 bytes long (RFC 4226 §4).');

        // When
        new TotpSecret(str_repeat('a', 15));
    }
}
