<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit\Regression;

use Beffroi\Xml\Core\CanonicalizationMethod;
use Beffroi\Xml\Core\Canonicalizer;
use Beffroi\Xml\Core\CanonicalXml;
use Beffroi\Xml\Core\DocumentFactory;
use Beffroi\Xml\Core\Exception\CanonicalizationFailed;
use Beffroi\Xml\Core\Name;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 3, CVE-2025-66578, I-13
 */
final class EmptyCanonicalFormTest extends TestCase
{
    /**
     * CVE-2025-66578
     */
    #[Test]
    public function cve202566578AFailedCanonicalizationIsARefusalNotAString(): void
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
        new Canonicalizer()->canonicalize($root, CanonicalizationMethod::Exclusive);
    }

    /**
     * CVE-2025-66578
     */
    #[Test]
    public function cve202566578TheEmptyStringIsNeverACanonicalForm(): void
    {
        // Then
        $this->expectException(CanonicalizationFailed::class);
        $this->expectExceptionMessageIs('The canonical form is empty (I-13).');

        // When
        new CanonicalXml('');
    }
}
