<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit;

use Beffroi\Xml\Core\CanonicalizationMethod;
use Beffroi\Xml\Core\Canonicalizer;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\DocumentFactory;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Serializer;
use Beffroi\Xml\Tests\Core\Support\Loaded;
use Dom\XMLDocument;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 6.5
 */
final class DocumentFactoryTest extends TestCase
{
    private const string XMLNS = 'http://www.w3.org/2000/xmlns/';

    private DocumentFactory $factory;

    protected function setUp(): void
    {
        $this->factory = new DocumentFactory();
    }

    #[Test]
    public function itCreatesADocumentWhoseRootCarriesTheNameAndThePrefix(): void
    {
        // When
        $document = $this->factory->create(new Name('urn:oasis:names:tc:SAML:2.0:protocol', 'AuthnRequest'), 'samlp');

        // Then
        $root = $document->root();
        static::assertSame('AuthnRequest', $root->localName);
        static::assertSame('urn:oasis:names:tc:SAML:2.0:protocol', $root->namespaceURI);
        static::assertSame('samlp', $root->prefix);
        static::assertSame('samlp:AuthnRequest', $root->tagName);
    }

    #[Test]
    public function itCreatesARootWithoutAPrefixByDefault(): void
    {
        // When
        $root = $this->factory->create(new Name('urn:a', 'a'))->root();

        // Then
        static::assertNull($root->prefix);
        static::assertSame('urn:a', $root->namespaceURI);
    }

    #[Test]
    public function itCreatesARootInNoNamespace(): void
    {
        // When
        $root = $this->factory->create(new Name(null, 'a'))->root();

        // Then
        static::assertNull($root->namespaceURI);
        static::assertSame('a', $root->tagName);
    }

    /**
     * Section 6.5
     */
    #[Test]
    public function itCreatesAnXml10Utf8Document(): void
    {
        // When
        $xml = $this->factory->create(new Name('urn:a', 'a'))->root()->ownerDocument;

        // Then
        static::assertInstanceOf(XMLDocument::class, $xml);
        static::assertSame('1.0', $xml->xmlVersion);
        static::assertSame('UTF-8', $xml->xmlEncoding);
    }

    /**
     * Section 6.2
     */
    #[Test]
    public function itCreatesADocumentWithAnEmptyIndex(): void
    {
        // When
        $document = $this->factory->create(new Name('urn:a', 'a'));

        // Then
        static::assertFalse($document->hasId('_x'));
    }

    /**
     * §9.3 row 14, I-4
     */
    #[Test]
    public function itsDocumentOwnsWhatAConsumerBuildsUnderTheRoot(): void
    {
        // Given
        $document = $this->factory->create(new Name('urn:a', 'a'));
        $root = $document->root();
        $xml = $root->ownerDocument;
        static::assertNotNull($xml);

        // When
        $child = $root->appendChild($xml->createElementNS('urn:a', 'b'));

        // Then
        static::assertSame($document, Document::owning($root));
        static::assertSame($document, Document::owning($child));
    }

    /**
     * Section 6.5
     */
    #[Test]
    public function itCreatesADistinctDocumentEachTime(): void
    {
        // When
        $first = $this->factory->create(new Name('urn:a', 'a'));
        $second = $this->factory->create(new Name('urn:a', 'a'));

        // Then
        static::assertNotSame($first, $second);
        static::assertSame($first, Document::owning($first->root()));
        static::assertSame($second, Document::owning($second->root()));
    }

    /**
     * Section 6.5
     */
    #[Test]
    public function itDeclaresTheNamespaceOfARootWithAPrefix(): void
    {
        // When
        $root = $this->factory->create(new Name('urn:oasis:names:tc:SAML:2.0:protocol', 'AuthnRequest'), 'samlp')->root();

        // Then
        static::assertSame('urn:oasis:names:tc:SAML:2.0:protocol', $root->getAttributeNS(self::XMLNS, 'samlp'));
        static::assertSame(1, $root->attributes->length);
    }

    /**
     * Section 6.5, section 13
     */
    #[Test]
    public function itDeclaresTheDefaultNamespaceOfARootWithoutAPrefix(): void
    {
        // When
        $root = $this->factory->create(new Name('urn:a', 'a'))->root();

        // Then
        static::assertSame('urn:a', $root->getAttributeNS(self::XMLNS, 'xmlns'));
        static::assertSame(1, $root->attributes->length);
    }

    /**
     * Section 6.5
     */
    #[Test]
    public function itDeclaresNothingOnARootInNoNamespace(): void
    {
        // When
        $root = $this->factory->create(new Name(null, 'a'))->root();

        // Then
        static::assertSame(0, $root->attributes->length);
    }

    /**
     * §9.3 row 18, section 6.5
     */
    #[Test]
    public function itsRootCanonicalizesWithItsNamespaceBeforeAndAfterARoundTrip(): void
    {
        // Given
        $canonicalizer = new Canonicalizer();
        $document = $this->factory->create(new Name('urn:oasis:names:tc:SAML:2.0:protocol', 'Response'));
        $root = $document->root();
        $xml = $root->ownerDocument;
        static::assertNotNull($xml);
        $root->appendChild($xml->createElementNS(
            'urn:oasis:names:tc:SAML:2.0:assertion',
            'saml:Issuer',
        ))->appendChild($xml->createTextNode('https://idp.example.org'));

        // When
        $before = $canonicalizer->canonicalize($root, CanonicalizationMethod::Exclusive)->bytes;
        $reloaded = Loaded::document(new Serializer()->serialize($document));

        // Then
        static::assertSame(
            '<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol">'
            . '<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.org</saml:Issuer>'
            . '</Response>',
            $before,
        );
        static::assertSame(
            $before,
            $canonicalizer->canonicalize($reloaded->root(), CanonicalizationMethod::Exclusive)->bytes,
        );
    }
}
