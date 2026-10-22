<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\Response;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Internal\Response\DecryptedAssertion;
use Beffroi\Saml2\Model\Internal\Response\SignedResponse;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Enc\Decryptor;
use Beffroi\Xml\Enc\Exception\DecryptionFailed;
use Dom\Element;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * Section 6.7, M-4, M-14: the xenc:EncryptedData of the response as section 6.1 step 3 left it, decrypted by Enc with
 * the key of the service provider, its plaintext a saml:Assertion.
 */
final class DecryptedAssertionTest extends TestCase
{
    use ResponseFixtures;

    private const string XMLENC = 'http://www.w3.org/2001/04/xmlenc#';

    /**
     * §9.3 row 24, M-1, section 6.7: the ciphertext of a signed response is decrypted from the response as its
     * signature verified it, into a document whose root is the assertion: the ciphertext of the received document,
     * replaced once the signature was verified by bytes that decrypt to nothing, is not the one read.
     */
    #[Test]
    public function itDecryptsTheCiphertextOfTheVerifiedResponse(): void
    {
        // Given
        $document = $this->document('encrypted/response-signed-over-encrypted-assertion-accepted.xml');
        $response = SignedResponse::of($document->root(), self::identityProvider(), SamlLoader::create());
        $this->receivedCipherValue($document)->replaceChildren(str_repeat('A', 88));

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

    /**
     * §9.3 row 24: the ciphertext of the received document left as it is would decrypt; replaced, it does not, so that
     * the test above reads the verified one.
     */
    #[Test]
    public function theReplacedCiphertextOfTheReceivedDocumentDecryptsToNothing(): void
    {
        // Given
        $document = $this->document('encrypted/response-signed-over-encrypted-assertion-accepted.xml');
        $this->receivedCipherValue($document)->replaceChildren(str_repeat('A', 88));

        // Then
        $this->expectException(DecryptionFailed::class);
        $this->expectExceptionMessageIs('The data could not be decrypted (E-3).');

        // When
        new Decryptor(SamlLoader::create())->decrypt(
            Children::one(
                Children::one($document->root(), new Name(Saml::ASSERTION, 'EncryptedAssertion')),
                new Name(self::XMLENC, 'EncryptedData'),
            ),
            self::decryptionKey(),
        );
    }

    /**
     * The xenc:CipherValue of the content of the one saml:EncryptedAssertion of $document, as it was received.
     */
    private function receivedCipherValue(Document $document): Element
    {
        return Children::one(
            Children::one(
                Children::one(
                    Children::one($document->root(), new Name(Saml::ASSERTION, 'EncryptedAssertion')),
                    new Name(self::XMLENC, 'EncryptedData'),
                ),
                new Name(self::XMLENC, 'CipherData'),
            ),
            new Name(self::XMLENC, 'CipherValue'),
        );
    }
}
