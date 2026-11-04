<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Unit;

use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Text;
use Beffroi\Xml\Enc\ContentAlgorithm;
use Beffroi\Xml\Enc\Decryptor;
use Beffroi\Xml\Enc\EncryptedData;
use Beffroi\Xml\Enc\Exception\CoveringSignatureRequired;
use Beffroi\Xml\Enc\OaepHash;
use Beffroi\Xml\Enc\PrivateDecryptionKey;
use Beffroi\Xml\Tests\Core\Support\Stack;
use Beffroi\Xml\Tests\Enc\Support\CoveringDocument;
use Beffroi\Xml\Tests\Enc\Support\Encrypted;
use Beffroi\Xml\Tests\Enc\Support\Fixtures;
use Beffroi\Xml\Tests\Enc\Support\LoadedDocument;
use Beffroi\Xml\Tests\Enc\Support\Loaded;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;

/**
 * Section 9.4
 */
final class RealDocumentsTest extends TestCase
{
    /**
     * §9.4, section 13
     */
    #[Test]
    #[TestWith(
        ['simplesamlphp-xmlseclibs-3.1.5-response-encrypted-aes256-gcm-2026-09-27.xml', ContentAlgorithm::Aes256Gcm],
        'aes256-gcm',
    )]
    #[TestWith(
        ['simplesamlphp-xmlseclibs-3.1.5-response-encrypted-aes128-gcm-2026-09-27.xml', ContentAlgorithm::Aes128Gcm],
        'aes128-gcm',
    )]
    public function itDecryptsWhatSimpleSamlPhpsLibraryEncrypted(string $fixture, ContentAlgorithm $algorithm): void
    {
        // Given
        $document = Loaded::fixture('real/' . $fixture);
        $element = Encrypted::dataOf($document);
        $data = EncryptedData::of($element);
        static::assertSame($algorithm, $data->algorithm);
        static::assertSame(OaepHash::Sha1, $data->key->transport->hash);

        // When
        $decrypted = new Decryptor(new Loader(Stack::idAttributes()))->decrypt($element, $this->key());

        // Then
        $root = $decrypted->root();
        static::assertSame($root, $decrypted->elementById('_assertion-d4e5f6'));
        static::assertSame(
            'https://idp.example.org',
            Text::of(Children::one($root, new Name(Stack::SAML_ASSERTION, 'Issuer'))),
        );
        $nameId = Children::one(
            Children::one($root, new Name(Stack::SAML_ASSERTION, 'Subject')),
            new Name(Stack::SAML_ASSERTION, 'NameID'),
        );
        static::assertSame('user-0001', Text::of($nameId));
    }

    /**
     * §9.4, E-15
     */
    #[Test]
    public function itRefusesWhatSimpleSamlPhpsSetAssertionEncryptsByDefaultWithoutASignature(): void
    {
        // Given
        $document = Loaded::fixture('real/simplesamlphp-saml2-4.20.3-response-encrypted-assertion-default-2026-09-27.xml');
        $element = Encrypted::dataOf($document);

        // Then
        $this->expectException(CoveringSignatureRequired::class);
        $this->expectExceptionMessageIs('AES-CBC is decrypted only under a verified signature that covers the encrypted element (E-15).');

        // When
        new Decryptor(new Loader(Stack::idAttributes()))->decrypt($element, $this->key());
    }

    /**
     * §9.4, §9.3 row 22, E-15, E-16
     */
    #[Test]
    public function itDecryptsWhatSimpleSamlPhpsSetAssertionEncryptsByDefaultUnderASignature(): void
    {
        // Given
        $document = Loaded::fixture('real/simplesamlphp-saml2-4.20.3-response-encrypted-assertion-default-2026-09-27.xml');
        $element = Encrypted::dataOf($document);

        // When
        $decrypted = new Decryptor(new Loader(Stack::idAttributes()))->decryptCovered(
            $element,
            $this->key(),
            new CoveringDocument($document),
            new LoadedDocument(),
        );

        // Then
        static::assertSame(
            'https://idp.example.org',
            Text::of(Children::one($decrypted->root(), new Name(Stack::SAML_ASSERTION, 'Issuer'))),
        );
    }

    private function key(): PrivateDecryptionKey
    {
        return PrivateDecryptionKey::fromPem(Fixtures::bytes('keys/test-signing-key.pem'));
    }
}
