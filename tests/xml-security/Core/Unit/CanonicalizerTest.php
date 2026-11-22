<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit;

use function array_pop;
use Beffroi\Xml\Core\CanonicalizationMethod;
use Beffroi\Xml\Core\Canonicalizer;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\DocumentFactory;
use Beffroi\Xml\Core\Exception\CanonicalizationFailed;
use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Core\InclusiveNamespaces;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Serializer;
use Beffroi\Xml\Tests\Core\Support\Fixtures;
use Beffroi\Xml\Tests\Core\Support\Foreign;
use Beffroi\Xml\Tests\Core\Support\Libxml;
use Beffroi\Xml\Tests\Core\Support\Loaded;
use Beffroi\Xml\Tests\Core\Support\Nodes;
use Dom\Element;
use InvalidArgumentException;
use function libxml_use_internal_errors;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 6.3, section 9.1, I-14
 */
final class CanonicalizerTest extends TestCase
{
    private const string XMLNS = 'http://www.w3.org/2000/xmlns/';

    private Canonicalizer $canonicalizer;

    private Serializer $serializer;

    protected function setUp(): void
    {
        $this->canonicalizer = new Canonicalizer();
        $this->serializer = new Serializer();
    }

    /**
     * Section 9.1, Canonical XML 1.0 §3, Exclusive XML Canonicalization §2, section 13, section 9.3 (rows 1 and 2)
     *
     * @param list<string> $prefixes
     */
    #[Test]
    #[DataProvider('provideVectors')]
    public function itRendersAVectorByteForByte(
        string $fixture,
        ?string $apexName,
        CanonicalizationMethod $method,
        array $prefixes,
        string $expected,
    ): void {
        // Given
        $document = Loaded::fixture($fixture);
        $apex = $apexName === null ? $document->root() : Nodes::childNamed($document->root(), $apexName);
        // The serializer refuses the carriage return of the §3.4 vector (section 6.5), so the witness is a canonical form.
        $before = $this->canonicalizer->canonicalize($document->root(), CanonicalizationMethod::InclusiveWithComments);

        // When
        $canonical = $this->canonicalizer->canonicalize($apex, $method, new InclusiveNamespaces($prefixes));

        // Then
        static::assertSame(Fixtures::bytes($expected), $canonical->bytes);
        static::assertSame(
            $before->bytes,
            $this->canonicalizer->canonicalize($document->root(), CanonicalizationMethod::InclusiveWithComments)->bytes,
        );
    }

    /**
     * @return iterable<string, array{string, ?string, CanonicalizationMethod, list<string>, string}>
     */
    public static function provideVectors(): iterable
    {
        $inclusive = CanonicalizationMethod::Inclusive;
        $inclusiveWithComments = CanonicalizationMethod::InclusiveWithComments;
        $exclusive = CanonicalizationMethod::Exclusive;
        $c = 'canonical/';
        $b = 'behaviour/';

        yield 'C14N §3.1 A, outside nodes, inclusive' => [
            $c . 'c14n-3.1-derived-a-outside-nodes.xml',
            null,
            $inclusive,
            [],
            $c . 'c14n-3.1-derived-a-outside-nodes.inclusive.c14n',
        ];
        yield 'C14N §3.1 A, outside nodes, with comments' => [
            $c . 'c14n-3.1-derived-a-outside-nodes.xml',
            null,
            $inclusiveWithComments,
            [],
            $c . 'c14n-3.1-derived-a-outside-nodes.inclusive-with-comments.c14n',
        ];
        yield 'C14N §3.1 B, nodes inside doc, inclusive' => [
            $c . 'c14n-3.1-derived-b-nodes-inside-doc.xml',
            null,
            $inclusive,
            [],
            $c . 'c14n-3.1-derived-b-nodes-inside-doc.inclusive.c14n',
        ];
        yield 'C14N §3.1 B, nodes inside doc, with comments' => [
            $c . 'c14n-3.1-derived-b-nodes-inside-doc.xml',
            null,
            $inclusiveWithComments,
            [],
            $c . 'c14n-3.1-derived-b-nodes-inside-doc.inclusive-with-comments.c14n',
        ];
        yield 'C14N §3.2 whitespace in document content' => [
            $c . 'c14n-3.2-whitespace-in-content.xml',
            null,
            $inclusive,
            [],
            $c . 'c14n-3.2-whitespace-in-content.inclusive.c14n',
        ];
        yield 'C14N §3.3 start and end tags' => [
            $c . 'c14n-3.3-derived-start-and-end-tags.xml',
            null,
            $inclusive,
            [],
            $c . 'c14n-3.3-derived-start-and-end-tags.inclusive.c14n',
        ];
        yield 'C14N §3.4 character modifications and character references' => [
            $c . 'c14n-3.4-derived-character-references.xml',
            null,
            $inclusive,
            [],
            $c . 'c14n-3.4-derived-character-references.inclusive.c14n',
        ];
        yield 'C14N §3.6 UTF-8 encoding' => [
            $c . 'c14n-3.6-derived-utf-8.xml',
            null,
            $inclusive,
            [],
            $c . 'c14n-3.6-derived-utf-8.inclusive.c14n',
        ];
        yield 'Exclusive C14N §2.1, elem1 in pdu, inclusive' => [
            $c . 'exc-c14n-2.1-elem1-in-pdu.xml',
            'elem1',
            $inclusive,
            [],
            $c . 'exc-c14n-2.1-elem1-in-pdu.inclusive.c14n',
        ];
        yield 'Exclusive C14N §2.1, elem1 in pdu, exclusive' => [
            $c . 'exc-c14n-2.1-elem1-in-pdu.xml',
            'elem1',
            $exclusive,
            [],
            $c . 'exc-c14n-2.1-elem1-in-pdu.exclusive.c14n',
        ];
        yield 'Exclusive C14N §2.2, elem2 in local, inclusive' => [
            $c . 'exc-c14n-2.2-elem2-in-local.xml',
            'elem2',
            $inclusive,
            [],
            $c . 'exc-c14n-2.2-elem2-in-local.inclusive.c14n',
        ];
        yield 'Exclusive C14N §2.2, elem2 in local, exclusive' => [
            $c . 'exc-c14n-2.2-elem2-in-local.xml',
            'elem2',
            $exclusive,
            [],
            $c . 'exc-c14n-2.2-elem2-in-local.exclusive.c14n',
        ];
        yield 'Exclusive C14N §2.2, elem2 re-enveloped, inclusive' => [
            $c . 'exc-c14n-2.2-derived-elem2-re-enveloped.xml',
            'elem2',
            $inclusive,
            [],
            $c . 'exc-c14n-2.2-derived-elem2-re-enveloped.inclusive.c14n',
        ];
        yield 'Exclusive C14N §2.2, elem2 re-enveloped, exclusive' => [
            $c . 'exc-c14n-2.2-derived-elem2-re-enveloped.xml',
            'elem2',
            $exclusive,
            [],
            $c . 'exc-c14n-2.2-derived-elem2-re-enveloped.exclusive.c14n',
        ];
        yield 'measured, inclusive renders everything in scope and the inherited xml:lang' => [
            $c . 'measured-apex-under-ancestors.xml',
            'a',
            $inclusive,
            [],
            $c . 'measured-apex-under-ancestors.inclusive.c14n',
        ];
        yield 'measured, exclusive renders the visibly utilised namespaces only' => [
            $c . 'measured-apex-under-ancestors.xml',
            'a',
            $exclusive,
            [],
            $c . 'measured-apex-under-ancestors.exclusive.c14n',
        ];
        yield 'measured, exclusive with PrefixList="unused"' => [
            $c . 'measured-apex-under-ancestors.xml',
            'a',
            $exclusive,
            ['unused'],
            $c . 'measured-apex-under-ancestors.exclusive-prefixlist-unused.c14n',
        ];
        yield 'measured, exclusive with PrefixList="#default"' => [
            $c . 'measured-apex-under-ancestors.xml',
            'a',
            $exclusive,
            ['#default'],
            $c . 'measured-apex-under-ancestors.exclusive-prefixlist-default.c14n',
        ];
        yield 'measured, exclusive with an unknown prefix changes nothing' => [
            $c . 'measured-apex-under-ancestors.xml',
            'a',
            $exclusive,
            ['nope'],
            $c . 'measured-apex-under-ancestors.exclusive.c14n',
        ];
        yield '§9.3 row 1, comment-split NameID without comments' => [
            $b . 'nameid-comment-split.xml',
            null,
            $inclusive,
            [],
            $b . 'nameid-comment-split.inclusive.c14n',
        ];
        yield '§9.3 row 1, comment-split NameID with comments' => [
            $b . 'nameid-comment-split.xml',
            null,
            $inclusiveWithComments,
            [],
            $b . 'nameid-comment-split.inclusive-with-comments.c14n',
        ];
        yield '§9.3 row 2, CDATA folded' => [
            $b . 'cdata-in-text.xml',
            null,
            $inclusive,
            [],
            $b . 'cdata-in-text.inclusive.c14n',
        ];
    }

    /**
     * §9.3 row 12, I-14
     */
    #[Test]
    #[DataProvider('provideEnvelopedCases')]
    public function itExcludesASubtreeAsTheXpathNodeSetWould(
        string $fixture,
        CanonicalizationMethod $method,
        string $expected,
    ): void {
        // Given
        $document = Loaded::fixture($fixture);
        $before = $this->serializer->serialize($document);
        $signatures = $this->signaturesOf($document);

        // When
        $canonical = $this->canonicalizer->canonicalize(
            $document->root(),
            $method,
            InclusiveNamespaces::none(),
            $signatures,
        );

        // Then
        static::assertSame(Fixtures::bytes($expected), $canonical->bytes);
        static::assertSame($before, $this->serializer->serialize($document));
    }

    /**
     * @return iterable<string, array{string, CanonicalizationMethod, string}>
     */
    public static function provideEnvelopedCases(): iterable
    {
        foreach ([
            'enveloped-signature-under-root',
            'enveloped-signature-first-child',
            'enveloped-signature-last-child',
            'enveloped-two-signatures',
        ] as $case) {
            yield $case . ', inclusive' => [
                'behaviour/' . $case . '.xml',
                CanonicalizationMethod::Inclusive,
                'behaviour/' . $case . '.inclusive.c14n',
            ];
            yield $case . ', exclusive' => [
                'behaviour/' . $case . '.xml',
                CanonicalizationMethod::Exclusive,
                'behaviour/' . $case . '.exclusive.c14n',
            ];
        }
    }

    /**
     * Section 6.3 step 4
     */
    #[Test]
    public function itReinsertsAdjacentExclusionsWhateverTheirOrder(): void
    {
        // Given
        $document = Loaded::document('<r><a/><b/><c/></r>');
        $root = $document->root();
        $before = $this->serializer->serialize($document);

        // When
        $canonical = $this->canonicalizer->canonicalize(
            $root,
            CanonicalizationMethod::Inclusive,
            InclusiveNamespaces::none(),
            [Nodes::childNamed($root, 'b'), Nodes::childNamed($root, 'a')],
        );

        // Then
        static::assertSame('<r><c></c></r>', $canonical->bytes);
        static::assertSame($before, $this->serializer->serialize($document));
    }

    /**
     * Section 6.3 step 3
     */
    #[Test]
    public function itReinsertsANestedExclusion(): void
    {
        // Given
        $document = Loaded::document('<r><a><b/></a><c/></r>');
        $root = $document->root();
        $a = Nodes::childNamed($root, 'a');
        $before = $this->serializer->serialize($document);

        // When
        $canonical = $this->canonicalizer->canonicalize(
            $root,
            CanonicalizationMethod::Inclusive,
            InclusiveNamespaces::none(),
            [Nodes::childNamed($a, 'b'), $a],
        );

        // Then
        static::assertSame('<r><c></c></r>', $canonical->bytes);
        static::assertSame($before, $this->serializer->serialize($document));
    }

    /**
     * §9.3 row 13, I-14
     */
    #[Test]
    public function itPutsTheExclusionsBackWhenTheCanonicalizationFails(): void
    {
        // Given
        $document = Loaded::fixture('behaviour/enveloped-signature-under-root.xml');
        $root = $document->root();
        $xml = $root->ownerDocument;
        static::assertNotNull($xml);
        $root->appendChild($xml->createElementNS('relative', 'x:b'));
        $before = $this->serializer->serialize($document);

        // When
        try {
            $this->canonicalizer->canonicalize(
                $root,
                CanonicalizationMethod::Exclusive,
                InclusiveNamespaces::none(),
                $this->signaturesOf($document),
            );
        } catch (CanonicalizationFailed) {
        }

        // Then
        static::assertSame($before, $this->serializer->serialize($document));
    }

    /**
     * §9.2 row 29, I-13, I-16
     */
    #[Test]
    public function itRefusesARelativeNamespaceLibxmlCannotCanonicalize(): void
    {
        // Given
        $document = new DocumentFactory()->create(new Name('urn:a', 'a'));
        $root = $document->root();
        $xml = $root->ownerDocument;
        static::assertNotNull($xml);
        $root->appendChild($xml->createElementNS('relative', 'x:b'));

        // Then
        $this->expectException(CanonicalizationFailed::class);
        $this->expectExceptionMessageIs('libxml could not canonicalize the apex: error 1955 (I-13).');

        // When
        $this->canonicalizer->canonicalize($root, CanonicalizationMethod::Inclusive);
    }

    /**
     * §9.2 row 26, I-4
     */
    #[Test]
    public function itRefusesAForeignApex(): void
    {
        // Given
        $root = Foreign::parse('<a/>')->documentElement;
        static::assertNotNull($root);

        // Then
        $this->expectException(ForeignNode::class);
        $this->expectExceptionMessageIs('The node belongs to a document the brick did not produce (I-4).');

        // When
        $this->canonicalizer->canonicalize($root, CanonicalizationMethod::Inclusive);
    }

    /**
     * §9.2 row 27, section 6.3 step 1
     */
    #[Test]
    public function itRefusesAnApexThatIsNotConnected(): void
    {
        // Given
        $document = Loaded::document('<r><a><b/></a></r>');
        $root = $document->root();
        $a = Nodes::childNamed($root, 'a');
        $root->removeChild($a);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The apex is not connected to its document (section 6.3).');

        // When
        $this->canonicalizer->canonicalize(
            $a,
            CanonicalizationMethod::Inclusive,
            InclusiveNamespaces::none(),
            [Nodes::childNamed($a, 'b')],
        );
    }

    /**
     * §9.2 row 27
     */
    #[Test]
    public function itDetachesNothingWhenTheApexIsNotConnected(): void
    {
        // Given
        $document = Loaded::document('<r><a><b/></a></r>');
        $root = $document->root();
        $a = Nodes::childNamed($root, 'a');
        $b = Nodes::childNamed($a, 'b');
        $root->removeChild($a);

        // When
        try {
            $this->canonicalizer->canonicalize(
                $a,
                CanonicalizationMethod::Inclusive,
                InclusiveNamespaces::none(),
                [$b],
            );
        } catch (InvalidArgumentException) {
        }

        // Then
        static::assertSame($a, $b->parentNode);
    }

    /**
     * §9.2 row 28, section 6.3 step 3
     */
    #[Test]
    #[DataProvider('provideNonDescendants')]
    public function itRefusesAnExclusionThatIsNotAStrictDescendant(string $which): void
    {
        // Given
        $document = Loaded::document('<r><a><b/></a><c/></r>');
        $other = Loaded::document('<o/>');
        $apex = Nodes::childNamed($document->root(), 'a');
        $excluded = match ($which) {
            'the apex itself' => $apex,
            'a sibling of the apex' => Nodes::childNamed($document->root(), 'c'),
            'the parent of the apex' => $document->root(),
            default => $other->root(),
        };

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An excluded element is not a strict descendant of the apex (section 6.3).');

        // When
        $this->canonicalizer->canonicalize(
            $apex,
            CanonicalizationMethod::Inclusive,
            InclusiveNamespaces::none(),
            [$excluded],
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNonDescendants(): iterable
    {
        foreach ([
            'the apex itself',
            'a sibling of the apex',
            'the parent of the apex',
            'the root of another document',
        ] as $which) {
            yield $which => [$which];
        }
    }

    /**
     * §9.2 row 28, I-14
     */
    #[Test]
    public function itLeavesTheDocumentUnchangedAfterRefusingAnExclusion(): void
    {
        // Given
        $document = Loaded::document('<r><a><b/></a><c/></r>');
        $root = $document->root();
        $before = $this->serializer->serialize($document);

        // When
        try {
            $this->canonicalizer->canonicalize($root, CanonicalizationMethod::Inclusive, InclusiveNamespaces::none(), [
                Nodes::childNamed($root, 'c'),
                $root,
            ]);
        } catch (InvalidArgumentException) {
        }

        // Then
        static::assertSame($before, $this->serializer->serialize($document));
    }

    /**
     * Section 6.3 step 3
     */
    #[Test]
    public function itRefusesAnElementExcludedTwice(): void
    {
        // Given
        $document = Loaded::document('<r><a/></r>');
        $root = $document->root();
        $a = Nodes::childNamed($root, 'a');

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An element is excluded twice (section 6.3).');

        // When
        $this->canonicalizer->canonicalize(
            $root,
            CanonicalizationMethod::Inclusive,
            InclusiveNamespaces::none(),
            [$a, $a],
        );
    }

    /**
     * §9.2 row 31, section 6.3
     */
    #[Test]
    #[DataProvider('provideInclusiveMethods')]
    public function itRefusesInclusiveNamespacesWithAnInclusiveMethod(CanonicalizationMethod $method): void
    {
        // Given
        $document = Loaded::document('<r xmlns:x="urn:x"/>');
        $root = $document->root();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('Inclusive namespaces apply to exclusive canonicalization only (section 6.3).');

        // When
        $this->canonicalizer->canonicalize($root, $method, new InclusiveNamespaces(['x']));
    }

    /**
     * @return iterable<string, array{CanonicalizationMethod}>
     */
    public static function provideInclusiveMethods(): iterable
    {
        yield 'inclusive' => [CanonicalizationMethod::Inclusive];
        yield 'inclusive with comments' => [CanonicalizationMethod::InclusiveWithComments];
    }

    /**
     * Section 6.3 step 4
     */
    #[Test]
    public function itAcceptsAnEmptyPrefixListWithAnExclusiveMethod(): void
    {
        // Given
        $document = Loaded::document('<r xmlns:x="urn:x"><x:a/></r>');
        $root = $document->root();

        // When
        $canonical = $this->canonicalizer->canonicalize(
            $root,
            CanonicalizationMethod::ExclusiveWithComments,
            InclusiveNamespaces::none(),
        );

        // Then
        static::assertSame('<r><x:a xmlns:x="urn:x"></x:a></r>', $canonical->bytes);
    }

    /**
     * Section 6.3 step 5
     */
    #[Test]
    public function itRestoresAnInternalErrorsModeOfFalseAfterACanonicalization(): void
    {
        // Given
        $document = Loaded::document('<r/>');
        $root = $document->root();
        libxml_use_internal_errors(false);

        // When
        $this->canonicalizer->canonicalize($root, CanonicalizationMethod::Inclusive);

        // Then
        static::assertFalse(Libxml::mode());
    }

    /**
     * Section 6.3 step 5
     */
    #[Test]
    public function itEmptiesTheBufferAndRestoresTheModeAfterARefusal(): void
    {
        // Given
        $document = new DocumentFactory()->create(new Name('urn:a', 'a'));
        $root = $document->root();
        $xml = $root->ownerDocument;
        static::assertNotNull($xml);
        $root->appendChild($xml->createElementNS('relative', 'x:b'));
        Libxml::fillBuffer();

        // When
        try {
            $this->canonicalizer->canonicalize($root, CanonicalizationMethod::Inclusive);
        } catch (CanonicalizationFailed) {
        }

        // Then
        static::assertSame([], Libxml::buffer());
        static::assertTrue(Libxml::mode());
    }

    /**
     * Section 6.6
     */
    #[Test]
    public function itsCanonicalFormLoadsAgainAsOneRootWithItsInheritedContext(): void
    {
        // Given
        $document = Loaded::fixture('canonical/measured-apex-under-ancestors.xml');
        $apex = Nodes::childNamed($document->root(), 'a');

        // When
        $reloaded = Loaded::document($this->canonicalizer->canonicalize(
            $apex,
            CanonicalizationMethod::Inclusive,
        )->bytes);

        // Then
        static::assertSame('a', $reloaded->root()->localName);
        static::assertSame('urn:s', $reloaded->root()->namespaceURI);
        static::assertSame('fr', $reloaded->root()->getAttributeNS('http://www.w3.org/XML/1998/namespace', 'lang'));
        static::assertSame('1', $reloaded->root()->getAttributeNS('urn:x', 'attr'));
        static::assertNull($reloaded->root()->parentElement);
    }

    /**
     * @return list<Element>
     */
    private function signaturesOf(Document $document): array
    {
        $signatures = [];
        $stack = [$document->root()];
        while ($stack !== []) {
            $element = array_pop($stack);
            if ($element->namespaceURI === 'http://www.w3.org/2000/09/xmldsig#' && $element->localName === 'Signature') {
                $signatures[] = $element;
                continue;
            }
            for ($child = $element->lastElementChild; $child !== null; $child = $child->previousElementSibling) {
                $stack[] = $child;
            }
        }

        return $signatures;
    }

    /**
     * §9.3 row 19, section 6.3 step 2, section 13
     */
    #[Test]
    public function itRefusesABuiltElementWithoutAPrefixWhoseNamespaceNoDeclarationCovers(): void
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
        $this->canonicalizer->canonicalize($root, CanonicalizationMethod::Exclusive);
    }

    /**
     * §9.3 row 19, section 6.3 step 2, section 13
     */
    #[Test]
    public function itRefusesABuiltChildInNoNamespaceUnderADefaultNamespaceWithoutItsOwnEmptyDeclaration(): void
    {
        // Given
        $document = new DocumentFactory()->create(new Name('urn:a', 'a'));
        $root = $document->root();
        $xml = $root->ownerDocument;
        static::assertNotNull($xml);
        $root->appendChild($xml->createElementNS(null, 'c'));

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An element without a prefix has no xmlns attribute in scope that declares its namespace (section 6.3).');

        // When
        $this->canonicalizer->canonicalize($root, CanonicalizationMethod::Inclusive);
    }

    /**
     * §9.3 row 19, section 6.3 step 2
     */
    #[Test]
    public function itRefusesAnUndeclaredDefaultNamespaceBeforeDetachingAnything(): void
    {
        // Given
        $document = new DocumentFactory()->create(new Name('urn:a', 'a'));
        $root = $document->root();
        $xml = $root->ownerDocument;
        static::assertNotNull($xml);
        $excluded = $xml->createElementNS('urn:ds', 'ds:Signature');
        $root->appendChild($excluded);
        $root->appendChild($xml->createElementNS('urn:b', 'b'));

        // When
        try {
            $this->canonicalizer->canonicalize($root, CanonicalizationMethod::Exclusive, excluding: [$excluded]);
        } catch (InvalidArgumentException) {
        }

        // Then
        static::assertSame($root, $excluded->parentNode);
        static::assertSame($excluded, $root->firstChild);
    }

    /**
     * §9.3 row 18, section 6.3 step 2
     */
    #[Test]
    public function itRendersTheDeclarationsBuiltElementsCarry(): void
    {
        // Given
        $document = new DocumentFactory()->create(new Name('urn:a', 'a'));
        $root = $document->root();
        $xml = $root->ownerDocument;
        static::assertNotNull($xml);
        $b = $xml->createElementNS('urn:b', 'b');
        $b->setAttributeNS(self::XMLNS, 'xmlns', 'urn:b');
        $root->appendChild($b);
        $c = $xml->createElementNS(null, 'c');
        $c->setAttributeNS(self::XMLNS, 'xmlns', '');
        $root->appendChild($c);
        $root->appendChild($xml->createElementNS('urn:d', 'q:d'));

        // When
        $bytes = $this->canonicalizer->canonicalize($root, CanonicalizationMethod::Inclusive)->bytes;

        // Then
        static::assertSame(
            '<a xmlns="urn:a"><b xmlns="urn:b"></b><c xmlns=""></c><q:d xmlns:q="urn:d"></q:d></a>',
            $bytes,
        );
        $reloaded = Loaded::document($this->serializer->serialize($document));
        static::assertSame(
            $bytes,
            $this->canonicalizer->canonicalize($reloaded->root(), CanonicalizationMethod::Inclusive)->bytes,
        );
    }

    /**
     * Section 6.3 step 2
     */
    #[Test]
    public function itReadsTheDeclarationsAboveTheApex(): void
    {
        // Given
        $document = new DocumentFactory()->create(new Name('urn:a', 'a'));
        $root = $document->root();
        $xml = $root->ownerDocument;
        static::assertNotNull($xml);
        $apex = $xml->createElementNS('urn:a', 'b');
        $root->appendChild($apex);

        // When
        $bytes = $this->canonicalizer->canonicalize($apex, CanonicalizationMethod::Exclusive)->bytes;

        // Then
        static::assertSame('<b xmlns="urn:a"></b>', $bytes);
    }
}
