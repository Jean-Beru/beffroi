<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\Response;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Internal\Response\DecryptedAssertion;
use Beffroi\Saml2\Model\Internal\Response\SignedResponse;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Name;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 6.7, M-4, M-14: the xenc:EncryptedData of the response as section 6.1 step 3 left it, decrypted by Enc with
 * the key of the service provider, its plaintext a saml:Assertion.
 */
final class DecryptedAssertionTest extends TestCase
{
    use ResponseFixtures;

    /**
     * §9.3 row 24, section 6.7: the ciphertext of a signed response is decrypted from the response as its signature
     * verified it, into a document whose root is the assertion.
     */
    #[Test]
    public function itDecryptsTheAssertionOfTheVerifiedResponse(): void
    {
        // Given
        $document = $this->document('encrypted/response-signed-over-encrypted-assertion-accepted.xml');
        $response = SignedResponse::of($document->root(), self::identityProvider(), SamlLoader::create());

        // When
        $decrypted = DecryptedAssertion::of($response, self::decryptionKey(), SamlLoader::create());

        // Then
        static::assertSame(
            ['saml:Assertion', '_assertion'],
            [
                $decrypted->document->root()->nodeName,
                Attributes::optional($decrypted->document->root(), new Name(null, 'ID')),
            ],
        );
    }

    /**
     * §9.2 row 41, M-4: a plaintext whose root is not a saml:Assertion, a samlp:Response here, is refused.
     */
    #[Test]
    public function itRefusesAPlaintextThatIsNotAnAssertion(): void
    {
        // Given
        $document = $this->document('encrypted/response-encrypted-not-an-assertion-refused.xml');
        $response = SignedResponse::of($document->root(), self::identityProvider(), SamlLoader::create());
        $message = 'The plaintext of the saml:EncryptedAssertion is not a saml:Assertion (M-4).';

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        DecryptedAssertion::of($response, self::decryptionKey(), SamlLoader::create());
    }
}
