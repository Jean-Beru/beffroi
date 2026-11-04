<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\Response;

use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Internal\Assertion\AssertionContext;
use Beffroi\Saml2\Model\Internal\Response\PlaintextReader;
use Beffroi\Saml2\Model\Internal\Response\SignedResponse;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Validation\TimeBounds;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Enc\Decryptor;
use Beffroi\Xml\Enc\Exception\DecryptionFailed;
use DateTimeImmutable;
use Dom\Element;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * Section 6.7 steps 3 to 5, M-1, M-14, enc.md E-15, E-16
 */
final class PlaintextReaderTest extends TestCase
{
    use ResponseFixtures;

    private const string XMLENC = 'http://www.w3.org/2001/04/xmlenc#';

    /**
     * §9.3 row 24, M-1, section 6.7
     */
    #[Test]
    public function itDecryptsTheCiphertextOfTheVerifiedResponse(): void
    {
        // Given
        $document = $this->document('encrypted/response-signed-over-encrypted-assertion-accepted.xml');
        $response = SignedResponse::of($document->root(), self::identityProvider(), SamlLoader::create());
        $this->receivedCipherValue($document)->replaceChildren(str_repeat('A', 88));

        // When
        $read = PlaintextReader::decrypt(
            $response,
            self::identityProvider()->withDecryptionKey(self::decryptionKey()),
            SamlLoader::create(),
            self::context(),
        );

        // Then
        static::assertSame(['_assertion', false], [$read->assertion->id, $read->signed]);
    }

    /**
     * §9.3 row 24
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
     * §9.3 row 23, M-2, section 6.7
     */
    #[Test]
    public function itReadsTheSignedAssertionOfAnUnsignedResponse(): void
    {
        // Given
        $document = $this->document('encrypted/response-encrypted-signed-assertion-accepted.xml');
        $response = SignedResponse::of($document->root(), self::identityProvider(), SamlLoader::create());

        // When
        $read = PlaintextReader::decrypt(
            $response,
            self::identityProvider()->withDecryptionKey(self::decryptionKey()),
            SamlLoader::create(),
            self::context(),
        );

        // Then
        static::assertSame(['_assertion', true], [$read->assertion->id, $read->signed]);
    }

    /**
     * §9.2 row 44, section 5.5, section 6.7
     */
    #[Test]
    public function itRefusesAProviderGivenNoKey(): void
    {
        // Given
        $document = $this->document('encrypted/response-signed-over-encrypted-assertion-accepted.xml');
        $response = SignedResponse::of($document->root(), self::identityProvider(), SamlLoader::create());

        // Then
        $this->expectException(Unsupported::class);
        $this->expectExceptionMessageIs('The response holds a saml:EncryptedAssertion and the identity provider was given no key to decrypt it (section 6.7).');

        // When
        PlaintextReader::decrypt($response, self::identityProvider(), SamlLoader::create(), self::context());
    }

    private static function context(): AssertionContext
    {
        return new AssertionContext(
            new DateTimeImmutable('2026-09-30T12:00:00Z'),
            new TimeBounds(),
            'https://idp.example.com/saml',
            'https://sp.example.com/saml',
            'https://sp.example.com/saml/acs',
            '_request',
        );
    }

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
