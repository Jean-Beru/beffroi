<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit\Regression;

use Beffroi\Xml\Core\Exception\DoctypeRefused;
use Beffroi\Xml\Core\Exception\ParserDiagnostic;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Tests\Core\Support\Stack;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 3, CVE-2025-25291, CVE-2025-25292, I-1, I-3, I-4
 */
final class RubySamlParserDifferentialTest extends TestCase
{
    private Loader $loader;

    protected function setUp(): void
    {
        $this->loader = new Loader(Stack::idAttributes());
    }

    /**
     * CVE-2025-25291
     */
    #[Test]
    public function cve202525291ADoctypeInAResponseIsRefusedBeforeAnyParserSeesIt(): void
    {
        // Given
        $bytes =
            '<!DOCTYPE samlp:Response [<!ENTITY assertion "">]>'
            . '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r">&assertion;</samlp:Response>';

        // Then
        $this->expectException(DoctypeRefused::class);
        $this->expectExceptionMessageIs('The input contains a document type declaration (I-1).');

        // When
        $this->loader->load($bytes);
    }

    /**
     * CVE-2025-25292
     */
    #[Test]
    public function cve202525292ANamespaceTheParsersDisagreeOnIsRefusedAtParsing(): void
    {
        // Given
        $bytes = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r"><saml:Assertion ID="_a"/></samlp:Response>';

        // Then
        $this->expectException(ParserDiagnostic::class);
        $this->expectExceptionMessageIs('libxml reported a diagnostic: error 201, level 2, at line 1, column 99 (I-3).');

        // When
        $this->loader->load($bytes);
    }
}
