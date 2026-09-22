<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Client;

use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Oidc\Domain\Client\ResponseEncryption;
use Heidi\Oidc\Domain\Client\ResponseFormat;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Registration §2: the shape a client registered for one kind of document the provider hands it.
 */
final class ResponseFormatTest extends TestCase
{
    /**
     * A client that registers nothing has the document signed with what the provider signs with, which is
     * what a null algorithm says.
     */
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
     * OIDC Core §5.3.2: the UserInfo answer is the one document a client may receive without a signature.
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
     * §5.3.2 again: an answer may be encrypted without being signed, and what the JWE carries is then the
     * document itself.
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
