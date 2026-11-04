<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit\Regression;

use Beffroi\Xml\Core\CanonicalizationMethod;
use Beffroi\Xml\Core\Canonicalizer;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Exception\DuplicateId;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Tests\Core\Support\Loaded;
use Beffroi\Xml\Tests\Core\Support\Stack;
use Beffroi\Xml\Core\Text;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * Section 3, CVE-2026-63182, I-8, I-11, section 6.6
 */
final class SignatureWrappingTest extends TestCase
{
    private const string RESPONSE =
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r">'
            . '<samlp:Extensions><saml:Assertion ID="%s"><saml:Subject><saml:NameID>signed@example.org</saml:NameID></saml:Subject></saml:Assertion></samlp:Extensions>'
            . '<saml:Assertion ID="%s"><saml:Subject><saml:NameID>attacker@example.org</saml:NameID></saml:Subject></saml:Assertion>'
            . '</samlp:Response>';

    #[Test]
    public function onBreakingSaml2012TwoAssertionsSharingTheSignedIdRefuseTheDocument(): void
    {
        // Given
        $bytes = sprintf(self::RESPONSE, '_signed', '_signed');

        // Then
        $this->expectException(DuplicateId::class);
        $this->expectExceptionMessageIs('An ID value appears twice in the document (I-8).');

        // When
        new Loader(Stack::idAttributes())->load($bytes);
    }

    #[Test]
    public function onBreakingSaml2012AWrappedAssertionIsNotAChildOfTheResponse(): void
    {
        // Given
        $document = Loaded::document(sprintf(self::RESPONSE, '_signed', '_evil'));

        // When
        $assertion = Children::one($document->root(), new Name(Stack::SAML_ASSERTION, 'Assertion'));

        // Then
        static::assertSame('_evil', $assertion->getAttributeNS(null, 'ID'));
        static::assertSame('_signed', $document->elementById('_signed')->getAttributeNS(null, 'ID'));
    }

    /**
     * CVE-2026-63182, section 6.6
     */
    #[Test]
    public function cve202663182TheElementReceivedIsTheReparseOfTheBytesHashed(): void
    {
        // Given
        $document = Loaded::document(sprintf(self::RESPONSE, '_signed', '_evil'));
        $signed = $document->elementById('_signed');

        // When
        $hashed = new Canonicalizer()->canonicalize($signed, CanonicalizationMethod::Exclusive);
        $received = Loaded::document($hashed->bytes);

        // Then
        $root = $received->root();
        static::assertSame('Assertion', $root->localName);
        static::assertSame('_signed', $root->getAttributeNS(null, 'ID'));
        static::assertNull($root->parentElement);
        static::assertSame([], Children::named($root, new Name(Stack::SAML_PROTOCOL, 'Extensions')));
        static::assertFalse($received->hasId('_evil'));
        $nameId = Children::one(
            Children::one($root, new Name(Stack::SAML_ASSERTION, 'Subject')),
            new Name(Stack::SAML_ASSERTION, 'NameID'),
        );
        static::assertSame('signed@example.org', Text::of($nameId));
    }
}
