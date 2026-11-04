<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Credential;

use Beffroi\Core\Bridge\Random\PlatformRandomness;
use Beffroi\Core\Domain\Credential\TotpSecret;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use function strlen;

/**
 * RFC 4226 §4
 */
final class TotpSecretTest extends TestCase
{
    #[Test]
    public function aSecretDrawnAtItsOwnLengthIsTwentyBytes(): void
    {
        // When
        $secret = new TotpSecret(new PlatformRandomness()->bytes(TotpSecret::LENGTH));

        // Then
        static::assertSame(20, strlen($secret->bytes));
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
