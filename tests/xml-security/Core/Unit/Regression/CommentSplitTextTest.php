<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit\Regression;

use Beffroi\Xml\Core\CanonicalizationMethod;
use Beffroi\Xml\Core\Canonicalizer;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Tests\Core\Support\Loaded;
use Beffroi\Xml\Tests\Core\Support\Stack;
use Beffroi\Xml\Core\Text;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 3, CVE-2017-11427, CVE-2017-11428, CVE-2017-11429, CVE-2017-11430, CVE-2018-0489, CVE-2018-7340, I-12
 */
final class CommentSplitTextTest extends TestCase
{
    private const string RESPONSE =
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r">'
            . '<saml:Assertion ID="_a"><saml:Subject><saml:NameID>user@example.com<!---->.evil.com</saml:NameID></saml:Subject></saml:Assertion>'
            . '</samlp:Response>';

    /**
     * CVE-2017-11428, CVE-2018-0489
     */
    #[Test]
    public function cve201711428TheNameIdReadIsTheWholeTextAroundTheComment(): void
    {
        // Given
        $document = Loaded::document(self::RESPONSE);
        $subject = Children::one($document->elementById('_a'), new Name(Stack::SAML_ASSERTION, 'Subject'));

        // When
        $nameId = Text::of(Children::one($subject, new Name(Stack::SAML_ASSERTION, 'NameID')));

        // Then
        static::assertSame('user@example.com.evil.com', $nameId);
    }

    /**
     * CVE-2018-0489
     */
    #[Test]
    public function cve20180489TheCanonicalFormSignedCarriesTheWholeText(): void
    {
        // Given
        $document = Loaded::document(self::RESPONSE);

        // When
        $canonical = new Canonicalizer()->canonicalize($document->elementById('_a'), CanonicalizationMethod::Exclusive);

        // Then
        static::assertStringContainsString('<saml:NameID>user@example.com.evil.com</saml:NameID>', $canonical->bytes);
    }
}
