<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit;

use function array_map;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Exception\AmbiguousChild;
use Beffroi\Xml\Core\Exception\MissingChild;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Tests\Core\Support\Loaded;
use Beffroi\Xml\Tests\Core\Support\Stack;
use Dom\Element;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * I-11, section 6.4, I-10
 */
final class ChildrenTest extends TestCase
{
    private Name $assertion;

    protected function setUp(): void
    {
        $this->assertion = new Name(Stack::SAML_ASSERTION, 'Assertion');
    }

    /**
     * §9.3 row 5, I-11
     */
    #[Test]
    public function itFindsTheDirectChildOnlyAndNotTheWrappedOne(): void
    {
        // Given
        $document = Loaded::fixture('behaviour/assertion-wrapped-in-extensions.xml');

        // When
        $named = Children::named($document->root(), $this->assertion);

        // Then
        static::assertSame(
            ['_direct'],
            array_map(static fn (Element $element): ?string => $element->getAttributeNS(null, 'ID'), $named),
        );
        static::assertSame('_direct', Children::one($document->root(), $this->assertion)->getAttributeNS(null, 'ID'));
    }

    /**
     * §9.3 row 6, section 6.4
     */
    #[Test]
    public function oneRefusesTwoChildrenOfTheName(): void
    {
        // Given
        $document = Loaded::fixture('behaviour/response-two-assertions.xml');

        // Then
        $this->expectException(AmbiguousChild::class);
        $this->expectExceptionMessageIs('The element has more than one child named {urn:oasis:names:tc:SAML:2.0:assertion}Assertion (section 6.4).');

        // When
        Children::one($document->root(), $this->assertion);
    }

    /**
     * §9.3 row 6, section 6.4
     */
    #[Test]
    public function optionalRefusesTwoChildrenOfTheName(): void
    {
        // Given
        $document = Loaded::fixture('behaviour/response-two-assertions.xml');

        // Then
        $this->expectException(AmbiguousChild::class);
        $this->expectExceptionMessageIs('The element has more than one child named {urn:oasis:names:tc:SAML:2.0:assertion}Assertion (section 6.4).');

        // When
        Children::optional($document->root(), $this->assertion);
    }

    /**
     * §9.3 row 7, section 6.4
     */
    #[Test]
    public function oneRefusesAMissingChild(): void
    {
        // Given
        $document = Loaded::fixture('behaviour/response-without-assertion.xml');

        // Then
        $this->expectException(MissingChild::class);
        $this->expectExceptionMessageIs('The element has no child named {urn:oasis:names:tc:SAML:2.0:assertion}Assertion (section 6.4).');

        // When
        Children::one($document->root(), $this->assertion);
    }

    /**
     * §9.3 row 7, section 6.4
     */
    #[Test]
    public function optionalIsNullForAMissingChild(): void
    {
        // Given
        $document = Loaded::fixture('behaviour/response-without-assertion.xml');

        // When / Then
        static::assertNull(Children::optional($document->root(), $this->assertion));
    }

    /**
     * Section 6.4
     */
    #[Test]
    public function optionalReturnsTheOnlyChildOfTheName(): void
    {
        // Given
        $document = Loaded::fixture('behaviour/response-with-assertion.xml');

        // When
        $assertion = Children::optional($document->root(), $this->assertion);

        // Then
        static::assertNotNull($assertion);
        static::assertSame('_assertion', $assertion->getAttributeNS(null, 'ID'));
    }

    /**
     * §9.3 row 8, I-10
     */
    #[Test]
    public function itDoesNotMatchTheSameLocalNameInAnotherNamespace(): void
    {
        // Given
        $document = Loaded::fixture('behaviour/assertion-same-local-name-other-namespace.xml');

        // When / Then
        static::assertSame([], Children::named($document->root(), $this->assertion));
    }

    /**
     * §9.3 row 9, I-10
     */
    #[Test]
    public function itMatchesTheSameNamespaceUnderAnotherPrefix(): void
    {
        // Given
        $document = Loaded::fixture('behaviour/assertion-other-prefix.xml');

        // When
        $assertion = Children::one($document->root(), $this->assertion);

        // Then
        static::assertSame('_a', $assertion->getAttributeNS(null, 'ID'));
        static::assertSame('x', $assertion->prefix);
    }

    /**
     * I-11, section 5.5
     */
    #[Test]
    public function allListsTheElementChildrenInDocumentOrder(): void
    {
        // Given
        $document = Loaded::document('<r>text<a/><!--c--><b><c/></b><?pi?><d/></r>');

        // When
        $children = Children::all($document->root());

        // Then
        static::assertSame(
            ['a', 'b', 'd'],
            array_map(static fn (Element $element): string => $element->localName, $children),
        );
    }

    /**
     * I-11
     */
    #[Test]
    public function allIsEmptyForALeaf(): void
    {
        // Given
        $document = Loaded::document('<r>text only</r>');

        // When / Then
        static::assertSame([], Children::all($document->root()));
    }

    /**
     * Section 6.4
     */
    #[Test]
    public function namedListsEveryMatchingChildInOrder(): void
    {
        // Given
        $document = Loaded::document('<r xmlns:s="urn:oasis:names:tc:SAML:2.0:assertion"><x/><s:Assertion ID="_1"/><y/><s:Assertion ID="_2"/></r>');

        // When
        $named = Children::named($document->root(), $this->assertion);

        // Then
        static::assertSame(
            ['_1', '_2'],
            array_map(static fn (Element $element): ?string => $element->getAttributeNS(null, 'ID'), $named),
        );
    }

    /**
     * Section 6.4, I-16
     */
    #[Test]
    public function itNamesAChildInNoNamespaceWithoutBraces(): void
    {
        // Given
        $document = Loaded::document('<r/>');

        // Then
        $this->expectException(MissingChild::class);
        $this->expectExceptionMessageIs('The element has no child named child (section 6.4).');

        // When
        Children::one($document->root(), new Name(null, 'child'));
    }
}
