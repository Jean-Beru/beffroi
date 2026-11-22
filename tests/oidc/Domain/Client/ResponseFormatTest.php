<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Client;

use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Oidc\Domain\Client\ResponseEncryption;
use Beffroi\Oidc\Domain\Client\ResponseFormat;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Registration §2
 */
final class ResponseFormatTest extends TestCase
{
    #[Test]
    public function aSignedFormatWithoutAnAlgorithmTakesTheOneOfTheProvider(): void
    {
        // When
        $format = ResponseFormat::signed();

        // Then
        static::assertTrue($format->isSigned);
        static::assertNull($format->signature);
        static::assertFalse($format->isEncrypted());
        static::assertFalse($format->isPlain());
    }

    #[Test]
    public function aSignedFormatCarriesTheAlgorithmTheClientRegistered(): void
    {
        // When
        $format = ResponseFormat::signed(Algorithms::es256());

        // Then
        static::assertSame(Algorithms::es256(), $format->signature);
    }

    /**
     * OIDC Core §5.3.2
     */
    #[Test]
    public function anUnsignedFormatWithoutAnEncryptionIsThePlainDocument(): void
    {
        // When
        $format = ResponseFormat::unsigned();

        // Then
        static::assertFalse($format->isSigned);
        static::assertTrue($format->isPlain());
    }

    /**
     * OIDC Core §5.3.2
     */
    #[Test]
    public function anUnsignedFormatThatIsEncryptedIsNotPlain(): void
    {
        // Given
        $encryption = new ResponseEncryption(Algorithms::ecdhEsA256Kw(), Algorithms::a256Gcm());

        // When
        $format = ResponseFormat::unsigned($encryption);

        // Then
        static::assertFalse($format->isPlain());
        static::assertTrue($format->isEncrypted());
        static::assertSame($encryption, $format->encryption);
    }
}
