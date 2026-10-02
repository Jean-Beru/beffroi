<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Credential;

use Beffroi\Core\Domain\Credential\PlainPassword;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use function strlen;

/**
 * What a password has to be before anything hashes it: the lower bound of NIST SP 800-63B §5.1.1.2 in
 * characters, and the upper bound the password hashers refuse to go past (CVE-2013-1443) in bytes.
 * Whoever sets a password holds one of these, so the rule is not one a caller can go around.
 */
final class PlainPasswordTest extends TestCase
{
    /**
     * Eight characters, however many bytes they take.
     */
    #[Test]
    public function eightMultibyteCharactersAreLongEnough(): void
    {
        // When / Then
        static::assertSame('éééééééé', new PlainPassword('éééééééé')->value);
    }

    #[Test]
    public function sevenCharactersAreRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A password is at least 8 characters long.');

        // When
        new PlainPassword('seven77');
    }

    /**
     * The upper bound is counted in bytes, not in characters: it is what a hasher swallows.
     */
    #[Test]
    public function fourThousandAndNinetySixBytesAreAccepted(): void
    {
        // When / Then
        static::assertSame(PlainPassword::MAXIMUM_BYTES, strlen(new PlainPassword(str_repeat('a', PlainPassword::MAXIMUM_BYTES))->value));
    }

    #[Test]
    public function oneByteMoreIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A password is at most 4096 bytes long.');

        // When
        new PlainPassword(str_repeat('a', PlainPassword::MAXIMUM_BYTES + 1));
    }
}
