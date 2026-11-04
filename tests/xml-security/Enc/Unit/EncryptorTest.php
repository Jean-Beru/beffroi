<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Unit;

use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\CanonicalizationMethod;
use Beffroi\Xml\Core\Canonicalizer;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\DocumentFactory;
use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Core\Exception\MalformedXml;
use Beffroi\Xml\Core\InclusiveNamespaces;
use Beffroi\Xml\Core\Limits;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Serializer;
use Beffroi\Xml\Core\Text;
use Beffroi\Xml\Dsig\PrivateKey;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use Beffroi\Xml\Dsig\Signer;
use Beffroi\Xml\Dsig\VerificationKey;
use Beffroi\Xml\Dsig\VerificationKeys;
use Beffroi\Xml\Dsig\Verifier;
use Beffroi\Xml\Enc\ContentAlgorithm;
use Beffroi\Xml\Enc\Decryptor;
use Beffroi\Xml\Enc\EncryptedData;
use Beffroi\Xml\Enc\Encryptor;
use Beffroi\Xml\Enc\Exception\AlgorithmUnavailable;
use Beffroi\Xml\Enc\Exception\InvalidKey;
use Beffroi\Xml\Enc\KeyTransport;
use Beffroi\Xml\Enc\OaepHash;
use Beffroi\Xml\Enc\PeerKey;
use Beffroi\Xml\Enc\PrivateDecryptionKey;
use Beffroi\Xml\Tests\Core\Support\Foreign;
use Beffroi\Xml\Tests\Core\Support\Stack;
use Beffroi\Xml\Tests\Enc\Support\Built;
use Beffroi\Xml\Tests\Enc\Support\Encrypted;
use Beffroi\Xml\Tests\Enc\Support\Fixtures;
use Beffroi\Xml\Tests\Enc\Support\Loaded;
use Dom\Element;
use function explode;
use function implode;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;
use function preg_replace;
use function str_ends_with;
use function str_repeat;
use function strlen;
use function substr;

/**
 * Section 6.2, E-8, E-9
 */
final class EncryptorTest extends TestCase
{
    private const string XMLNS = 'http://www.w3.org/2000/xmlns/';

    private const string XS = 'http://www.w3.org/2001/XMLSchema';

    private const string XSI = 'http://www.w3.org/2001/XMLSchema-instance';

    private Encryptor $encryptor;

    private Decryptor $decryptor;

    private Canonicalizer $canonicalizer;

    private PeerKey $peer;

    private PrivateDecryptionKey $key;

    protected function setUp(): void
    {
        $this->encryptor = new Encryptor(new Loader(Stack::idAttributes()));
        $this->decryptor = new Decryptor(new Loader(Stack::idAttributes()));
        $this->canonicalizer = new Canonicalizer();
        $this->peer = PeerKey::fromCertificatePem(Fixtures::bytes('keys/test-signing-certificate.pem'));
        $this->key = PrivateDecryptionKey::fromPem(Fixtures::bytes('keys/test-signing-key.pem'));
    }

    /**
     * §9.3 row 3, E-9
     */
    #[Test]
    #[DataProvider('provideContentAlgorithms')]
    public function itEncryptsWhatTheDecryptorDecrypts(ContentAlgorithm $algorithm): void
    {
        // Given
        $document = Built::responseWithAssertion();
        $assertion = Built::assertionOf($document);
        $expected = $this->canonical($assertion);

        // When
        $encrypted = $this->encryptor->encrypt($assertion, $this->peer, $algorithm);

        // Then
        $data = EncryptedData::of($encrypted);
        static::assertSame($algorithm, $data->algorithm);
        static::assertSame(OaepHash::Sha1, $data->key->transport->hash);
        static::assertSame(256, strlen($data->key->cipherValue));
        static::assertSame(
            strlen($this->plaintext($assertion)) + ContentAlgorithm::IV_BYTES + ContentAlgorithm::TAG_BYTES,
            strlen($data->cipherValue),
        );
        $decrypted = $this->decryptor->decrypt($encrypted, $this->key);
        static::assertSame($expected, $this->canonical($decrypted->root()));
        static::assertSame($decrypted->root(), $decrypted->elementById(Built::ASSERTION_ID));
    }

    /**
     * @return iterable<string, array{ContentAlgorithm}>
     */
    public static function provideContentAlgorithms(): iterable
    {
        yield 'aes256-gcm' => [ContentAlgorithm::Aes256Gcm];
        yield 'aes128-gcm' => [ContentAlgorithm::Aes128Gcm];
    }

    /**
     * §9.3 row 4, section 13
     */
    #[Test]
    #[TestWith([OaepHash::Sha256], 'SHA-256')]
    #[TestWith([OaepHash::Sha384], 'SHA-384')]
    #[TestWith([OaepHash::Sha512], 'SHA-512')]
    public function itEncryptsUnderRsaOaepWhereTheBuildTakesADigest(OaepHash $hash): void
    {
        // Given
        $document = Built::responseWithAssertion();
        $assertion = Built::assertionOf($document);
        $expected = $this->canonical($assertion);
        if (! $hash->isAvailable()) {
            $this->expectException(AlgorithmUnavailable::class);
            $this->expectExceptionMessageIs('This build cannot wrap under a hash other than SHA-1: the RSA functions take no digest before PHP 8.5 (section 13).');
        }

        // When
        $encrypted = $this->encryptor->encrypt($assertion, $this->peer, transport: new KeyTransport($hash));

        // Then
        $data = EncryptedData::of($encrypted);
        static::assertSame($hash, $data->key->transport->hash);
        static::assertSame(KeyTransport::RSA_OAEP, Attributes::optional(
            Children::one($data->key->element, new Name(Stack::XMLENC, 'EncryptionMethod')),
            new Name(null, 'Algorithm'),
        ));
        $decrypted = $this->decryptor->decrypt($encrypted, $this->key);
        static::assertSame($expected, $this->canonical($decrypted->root()));
    }

    /**
     * §9.3 row 5, E-8
     */
    #[Test]
    public function itDrawsFreshRandomnessForEveryCall(): void
    {
        // Given
        $document = Built::responseWithAssertion();
        $assertion = Built::assertionOf($document);

        // When
        $first = EncryptedData::of($this->encryptor->encrypt($assertion, $this->peer));
        $second = EncryptedData::of($this->encryptor->encrypt($assertion, $this->peer));

        // Then
        static::assertNotSame($first->key->cipherValue, $second->key->cipherValue);
        static::assertNotSame($first->cipherValue, $second->cipherValue);
        static::assertNotSame(
            substr($first->cipherValue, 0, ContentAlgorithm::IV_BYTES),
            substr($second->cipherValue, 0, ContentAlgorithm::IV_BYTES),
        );
    }

    /**
     * §9.3 row 6
     */
    #[Test]
    public function itReturnsAnUnattachedElementOfTheGivenDocument(): void
    {
        // Given
        $document = Built::responseWithAssertion();
        $assertion = Built::assertionOf($document);
        $expected = $this->canonical($assertion);

        // When
        $encrypted = $this->encryptor->encrypt($assertion, $this->peer);

        // Then
        static::assertSame($assertion->ownerDocument, $encrypted->ownerDocument);
        static::assertNull($encrypted->parentNode);
        static::assertSame($document, Document::owning($encrypted));
        $bytes = new Serializer()->serialize($this->wrapped($document, $encrypted));
        static::assertStringContainsString(
            '<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>',
            $bytes,
        );
        static::assertStringContainsString(
            '<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>',
            $bytes,
        );
        static::assertStringContainsString('<xenc:CipherData><xenc:CipherValue>', $bytes);
        static::assertStringNotContainsString('<saml:Assertion', $bytes);
        $loaded = Loaded::document($bytes);
        $decrypted = $this->decryptor->decrypt(Encrypted::dataOf($loaded), $this->key);
        static::assertSame($expected, $this->canonical($decrypted->root()));
    }

    /**
     * §9.3 row 7
     */
    #[Test]
    public function itCarriesTheCertificateWhenGiven(): void
    {
        // Given
        $document = Built::responseWithAssertion();
        $assertion = Built::assertionOf($document);
        $pem = Fixtures::bytes('keys/test-signing-certificate.pem');
        $keyInfo = new Name(Stack::XMLDSIG, 'KeyInfo');

        // When
        $with = EncryptedData::of($this->encryptor->encrypt($assertion, $this->peer, certificatePem: $pem));
        $without = EncryptedData::of($this->encryptor->encrypt($assertion, $this->peer));

        // Then
        $certificate = Children::one(
            Children::one(Children::one($with->key->element, $keyInfo), new Name(Stack::XMLDSIG, 'X509Data')),
            new Name(Stack::XMLDSIG, 'X509Certificate'),
        );
        static::assertSame(preg_replace('~-----[A-Z ]+-----|\s~', '', $pem), Text::of($certificate));
        static::assertNull(Children::optional($without->key->element, $keyInfo));
        $decrypted = $this->decryptor->decrypt($with->element, $this->key);
        static::assertSame($this->canonical($assertion), $this->canonical($decrypted->root()));
    }

    /**
     * §9.3 row 8, E-9
     */
    #[Test]
    public function itEncryptsTheCanonicalFormWithComments(): void
    {
        // Given
        $document = Built::responseWithCommentedAssertion();
        $assertion = Built::assertionOf($document);
        static::assertNull(Attributes::optional($assertion, new Name(self::XMLNS, 'saml')));

        // When
        $decrypted = $this->decryptor->decrypt($this->encryptor->encrypt($assertion, $this->peer), $this->key);

        // Then
        $root = $decrypted->root();
        static::assertSame($this->canonical($assertion), $this->canonical($root));
        static::assertSame(Stack::SAML_ASSERTION, Attributes::optional($root, new Name(self::XMLNS, 'saml')));
        $nameId = Children::one(
            Children::one($root, new Name(Stack::SAML_ASSERTION, 'Subject')),
            new Name(Stack::SAML_ASSERTION, 'NameID'),
        );
        static::assertSame('user-0001', Text::of($nameId));
        static::assertStringContainsString('<!--' . Built::COMMENT . '-->', $this->canonical($nameId));
    }

    /**
     * §9.3 row 9
     */
    #[Test]
    public function itEncryptsASignedAssertionTheStackVerifiesAfterDecryption(): void
    {
        // Given
        $loader = new Loader(Stack::idAttributes());
        $signed = new Signer($loader)->sign(
            Built::responseWithAssertion(),
            Built::ASSERTION_ID,
            PrivateKey::fromPem(Fixtures::bytes('keys/test-signing-key.pem')),
            after: new Name(Stack::SAML_ASSERTION, 'Issuer'),
        );
        $trusted = new VerificationKeys([
            VerificationKey::fromCertificatePem(Fixtures::bytes('keys/test-signing-certificate.pem')),
        ]);

        // When
        $encrypted = $this->encryptor->encrypt(Built::assertionOf($signed), $this->peer);
        $decrypted = $this->decryptor->decrypt($encrypted, $this->key);

        // Then
        $verified = new Verifier($loader)->verify($decrypted->root(), $trusted);
        static::assertSame(SignatureAlgorithm::RsaSha256, $verified->algorithm);
        static::assertSame(Built::ASSERTION_ID, Attributes::optional(
            $verified->document->root(),
            new Name(null, 'ID'),
        ));
    }

    /**
     * §9.3 row 10
     */
    #[Test]
    #[TestWith(['encrypted-by-the-encryptor-aes256-gcm.xml'], 'aes256-gcm')]
    #[TestWith(['encrypted-by-the-encryptor-aes128-gcm.xml'], 'aes128-gcm')]
    public function itsOutputIsWhatXmlsec1Decrypted(string $fixture): void
    {
        // Given
        $document = Loaded::fixture('behaviour/' . $fixture);
        $built = Built::responseWithAssertion();
        $expected = $this->canonical(Built::assertionOf($built));

        // When
        $decrypted = $this->decryptor->decrypt(Encrypted::dataOf($document), $this->key);

        // Then
        static::assertSame($expected, $this->canonical($decrypted->root()));
    }

    /**
     * §9.3 row 11, core.md section 6.3
     */
    #[Test]
    public function itRefusesABuiltElementWhoseDefaultNamespaceIsUndeclared(): void
    {
        // Given
        $document = new DocumentFactory()->create(new Name('urn:a', 'a'));
        $root = $document->root();
        $xml = $root->ownerDocument;
        static::assertNotNull($xml);
        $root->appendChild($xml->createElementNS('urn:b', 'b'));

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An element without a prefix has no xmlns attribute in scope that declares its namespace (section 6.3).');

        // When
        $this->encryptor->encrypt($root, $this->peer);
    }

    /**
     * Section 6.3
     */
    #[Test]
    public function itRefusesADetachedElement(): void
    {
        // Given
        $document = Built::responseWithAssertion();
        $assertion = Built::assertionOf($document);
        $document->root()->removeChild($assertion);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The apex is not connected to its document (section 6.3).');

        // When
        $this->encryptor->encrypt($assertion, $this->peer);
    }

    /**
     * Core I-4
     */
    #[Test]
    public function itRefusesAForeignElement(): void
    {
        // Given
        $foreign = Foreign::parse(Fixtures::bytes('vectors/response-assertion.data.xml'));
        $element = $foreign->documentElement;
        static::assertInstanceOf(Element::class, $element);

        // Then
        $this->expectException(ForeignNode::class);

        // When
        $this->encryptor->encrypt($element, $this->peer);
    }

    /**
     * Section 6.2 step 6
     */
    #[Test]
    public function itWritesBase64InLinesOfSeventySixCharacters(): void
    {
        // Given
        $document = Built::responseWithAssertion();
        $cipherValue = new Name(Stack::XMLENC, 'CipherValue');
        $cipherData = new Name(Stack::XMLENC, 'CipherData');

        // When
        $data = EncryptedData::of($this->encryptor->encrypt(Built::assertionOf($document), $this->peer));

        // Then
        foreach ([$data->element, $data->key->element] as $element) {
            $text = Text::of(Children::one(Children::one($element, $cipherData), $cipherValue));
            static::assertFalse(str_ends_with($text, "\n"));
            $lines = explode("\n", $text);
            static::assertGreaterThan(1, count($lines));
            $last = array_pop($lines);
            foreach ($lines as $line) {
                static::assertSame(76, strlen($line));
            }
            static::assertGreaterThan(0, strlen($last));
            static::assertLessThanOrEqual(76, strlen($last));
        }
    }

    /**
     * §9.2 row 40, E-14
     */
    #[Test]
    #[DataProvider('provideHintsThatAreNotOneCertificate')]
    public function itRefusesACertificateHintThatIsNotOneCertificate(string $certificatePem): void
    {
        // Given
        $document = Built::responseWithAssertion();

        // Then
        $this->expectException(InvalidKey::class);
        $this->expectExceptionMessageIs('The certificate is one PEM block of type CERTIFICATE and nothing else (E-14).');

        // When
        $this->encryptor->encrypt(Built::assertionOf($document), $this->peer, certificatePem: $certificatePem);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideHintsThatAreNotOneCertificate(): iterable
    {
        $key = Fixtures::bytes('keys/test-signing-key.pem');
        $certificate = Fixtures::bytes('keys/test-signing-certificate.pem');

        yield 'a private key' => [$key];
        yield 'a key then a certificate' => [$key . $certificate];
        yield 'a certificate then a key' => [$certificate . $key];
        yield 'two certificates' => [$certificate . Fixtures::bytes('keys/stranger-certificate.pem')];
        yield 'text after the certificate' => [$certificate . 'x'];
        yield 'no content' => ["-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----\n"];
        yield 'content that is not base64' => ["-----BEGIN CERTIFICATE-----\nA===\n-----END CERTIFICATE-----\n"];
    }

    /**
     * §9.3 row 18, E-9
     */
    #[Test]
    public function itRendersThePrefixAQnameValueNames(): void
    {
        // Given
        $document = Built::responseWithAssertion();
        $root = $document->root();
        $root->setAttributeNS(self::XMLNS, 'xmlns:xs', self::XS);
        $root->setAttributeNS(self::XMLNS, 'xmlns:xsi', self::XSI);
        $assertion = Built::assertionOf($document);
        $this->attributeValue($assertion)->setAttributeNS(self::XSI, 'xsi:type', 'xs:string');

        // When
        $decrypted = $this->decryptor->decrypt($this->encryptor->encrypt($assertion, $this->peer), $this->key);

        // Then
        static::assertSame(self::XS, $this->attributeValue($decrypted->root())->lookupNamespaceURI('xs'));
    }

    /**
     * §9.3 row 19, E-9
     */
    #[Test]
    public function itRefusesAPlaintextNoParserAccepts(): void
    {
        // Given
        $document = Built::responseWithAssertion();
        $assertion = Built::assertionOf($document);
        $xml = $assertion->ownerDocument;
        static::assertNotNull($xml);
        $assertion->appendChild($xml->createElementNS('urn:vendor:ext?a=1&b=2', 'ext:Extra'));

        // Then
        $this->expectException(MalformedXml::class);

        // When
        $this->encryptor->encrypt($assertion, $this->peer);
    }

    /**
     * §9.3 row 20, E-9
     */
    #[Test]
    public function itHoldsThePlaintextToTheConsumersLimits(): void
    {
        // Given
        $document = Built::responseWithAssertion();
        $assertion = Built::assertionOf($document);
        $xml = $assertion->ownerDocument;
        static::assertNotNull($xml);
        $this->attributeValue($assertion)->appendChild($xml->createTextNode(str_repeat('a', 1_100_000)));
        $ceiling = new Encryptor(new Loader(Stack::idAttributes(), new Limits(maxBytes: 8_388_608)));

        // When
        $encrypted = $ceiling->encrypt($assertion, $this->peer);

        // Then
        static::assertGreaterThan(1_100_000, strlen(EncryptedData::of($encrypted)->cipherValue));
    }

    /**
     * E-9
     */
    private function canonical(Element $element): string
    {
        return $this->canonicalizer->canonicalize($element, CanonicalizationMethod::ExclusiveWithComments)->bytes;
    }

    /**
     * E-9
     */
    private function plaintext(Element $element): string
    {
        $prefixes = [];
        foreach ($element->getInScopeNamespaces() as $namespace) {
            $prefixes[] = $namespace->prefix ?? '#default';
        }

        return $this->canonicalizer->canonicalize(
            $element,
            CanonicalizationMethod::ExclusiveWithComments,
            InclusiveNamespaces::fromPrefixList(implode(' ', $prefixes)),
        )->bytes;
    }

    private function attributeValue(Element $assertion): Element
    {
        return Children::one(
            Children::one(
                Children::one($assertion, new Name(Stack::SAML_ASSERTION, 'AttributeStatement')),
                new Name(Stack::SAML_ASSERTION, 'Attribute'),
            ),
            new Name(Stack::SAML_ASSERTION, 'AttributeValue'),
        );
    }

    private function wrapped(Document $document, Element $encrypted): Document
    {
        $assertion = Built::assertionOf($document);
        $xml = $assertion->ownerDocument;
        static::assertNotNull($xml);
        $wrapper = $xml->createElementNS(Stack::SAML_ASSERTION, 'saml:EncryptedAssertion');
        $wrapper->appendChild($encrypted);
        $document->root()->replaceChild($wrapper, $assertion);

        return $document;
    }
}
