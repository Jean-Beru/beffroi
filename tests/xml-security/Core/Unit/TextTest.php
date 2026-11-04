<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit;

use Beffroi\Xml\Core\Exception\MixedContent;
use Beffroi\Xml\Tests\Core\Support\Foreign;
use Beffroi\Xml\Tests\Core\Support\Loaded;
use Beffroi\Xml\Core\Text;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * I-12, section 6.4, CVE-2017-11428, CVE-2018-0489
 */
final class TextTest extends TestCase
{
    /**
     * §9.3 row 1, I-12
     */
    #[Test]
    public function itConcatenatesTheTextAroundAComment(): void
    {
        // Given
        $document = Loaded::fixture('behaviour/nameid-comment-split.xml');

        // When / Then
        static::assertSame('user@example.com.evil.com', Text::of($document->root()));
    }

    /**
     * §9.3 row 2, I-12
     */
    #[Test]
    public function itReadsACdataSectionAsText(): void
    {
        // Given
        $document = Loaded::fixture('behaviour/cdata-in-text.xml');

        // When / Then
        static::assertSame('a<b>c', Text::of($document->root()));
    }

    /**
     * §9.3 row 3, I-12
     */
    #[Test]
    public function itRefusesAChildElement(): void
    {
        // Given
        $document = Loaded::fixture('behaviour/mixed-content-element-child.xml');

        // Then
        $this->expectException(MixedContent::class);
        $this->expectExceptionMessageIs('The element has a child that is neither text, CDATA, comment nor processing instruction (I-12).');

        // When
        Text::of($document->root());
    }

    /**
     * §9.3 row 4, I-12
     */
    #[Test]
    public function itSkipsAProcessingInstruction(): void
    {
        // Given
        $document = Loaded::fixture('behaviour/processing-instruction-in-text.xml');

        // When / Then
        static::assertSame('text', Text::of($document->root()));
    }

    /**
     * I-12
     */
    #[Test]
    public function itKeepsWhitespaceAndReadsAnEmptyElementAsEmpty(): void
    {
        // Given
        $document = Loaded::document('<r><a/><b> x </b></r>');
        $a = $document->root()->firstElementChild;
        static::assertNotNull($a);
        $b = $a->nextElementSibling;
        static::assertNotNull($b);

        // When / Then
        static::assertSame('', Text::of($a));
        static::assertSame(' x ', Text::of($b));
    }

    /**
     * I-12, section 6.4
     */
    #[Test]
    public function itRefusesAnEntityReferenceChild(): void
    {
        // Given
        $foreign = Foreign::parse('<!DOCTYPE doc [<!ENTITY x "y">]><doc>a&x;b</doc>');
        $root = $foreign->documentElement;
        static::assertNotNull($root);

        // Then
        $this->expectException(MixedContent::class);
        $this->expectExceptionMessageIs('The element has a child that is neither text, CDATA, comment nor processing instruction (I-12).');

        // When
        Text::of($root);
    }
}
