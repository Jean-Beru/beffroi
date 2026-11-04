<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Unit;

use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Enc\EncryptedKey;
use Beffroi\Xml\Enc\Exception\LimitExceeded;
use Beffroi\Xml\Enc\Exception\MalformedEncryption;
use Beffroi\Xml\Enc\Exception\UnknownKeyTransport;
use Beffroi\Xml\Enc\Internal\Names;
use Beffroi\Xml\Enc\KeyTransport;
use Beffroi\Xml\Enc\OaepHash;
use Beffroi\Xml\Tests\Core\Support\Foreign;
use Beffroi\Xml\Tests\Enc\Support\Encrypted;
use Beffroi\Xml\Tests\Enc\Support\Fixtures;
use Beffroi\Xml\Tests\Enc\Support\Loaded;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;
use function preg_replace;
use function str_repeat;
use function strlen;
use Throwable;

/**
 * Section 5.3, E-5, E-6, E-13
 */
final class EncryptedKeyTest extends TestCase
{
    /**
     * Section 5.3, §9.1 row 1
     */
    #[Test]
    public function itReadsTheKeyOfTheVector(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-encrypted-assertion-aes256-gcm.xml');
        $element = Encrypted::keyOf($document);

        // When
        $key = EncryptedKey::of($element);

        // Then
        static::assertSame($element, $key->element);
        static::assertSame(OaepHash::Sha1, $key->transport->hash);
        static::assertSame(KeyTransport::RSA_OAEP_MGF1P, $key->transport->uri());
        static::assertSame(256, strlen($key->cipherValue));
    }

    /**
     * §9.1 row 5
     */
    #[Test]
    public function itReadsTheKeyOfTheRsaOaepVector(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-encrypted-assertion-rsa-oaep-sha256.xml');

        // When
        $key = EncryptedKey::of(Encrypted::keyOf($document));

        // Then
        static::assertSame(OaepHash::Sha256, $key->transport->hash);
        static::assertSame(256, strlen($key->cipherValue));
    }

    /**
     * §9.1 row 3, E-6
     */
    #[Test]
    public function itReadsAKeyWithoutKeyInfo(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-encrypted-assertion-keyinfo-absent.xml');

        // When
        $key = EncryptedKey::of(Encrypted::keyOf($document));

        // Then
        static::assertSame(OaepHash::Sha1, $key->transport->hash);
        static::assertSame(256, strlen($key->cipherValue));
    }

    /**
     * E-6
     */
    #[Test]
    public function itNeverReadsTheKeyInfo(): void
    {
        // Given
        $bytes = preg_replace(
            '~<ds:X509Data>.*?</ds:X509Data>~s',
            '<ds:KeyName>anything</ds:KeyName><ds:RetrievalMethod URI="#nowhere"/><xenc:Unknown/>',
            Fixtures::bytes('vectors/response-encrypted-assertion-aes256-gcm.xml'),
        );
        static::assertNotNull($bytes);
        $document = Loaded::document($bytes);

        // When
        $key = EncryptedKey::of(Encrypted::keyOf($document));

        // Then
        static::assertSame(OaepHash::Sha1, $key->transport->hash);
        static::assertSame(256, strlen($key->cipherValue));
    }

    /**
     * §9.2 rows 3, 12 and 18, E-1, E-5, E-12, E-13
     *
     * @param class-string<Throwable> $exception
     */
    #[Test]
    #[DataProvider('provideRefusedShapes')]
    public function itRefusesAShapeOfTheHostileCorpus(string $fixture, string $exception, string $message): void
    {
        // Given
        $document = Loaded::fixture('hostile/' . $fixture);
        $element = Encrypted::keyOf($document);

        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($message);

        // When
        EncryptedKey::of($element);
    }

    /**
     * @return iterable<string, array{string, class-string<Throwable>, string}>
     */
    public static function provideRefusedShapes(): iterable
    {
        $otherChild = 'An EncryptedKey holds a child other than EncryptionMethod, KeyInfo and CipherData (E-5).';
        $bound = 'The cipher value of an EncryptedKey is not between 256 and maxEncryptedKeyBytes, 1024 bytes (E-13).';

        yield 'row 3, rsa-1_5' => [
            'key-transport-rsa-1-5-refused.xml',
            UnknownKeyTransport::class,
            'The key transport is not RSA-OAEP: PKCS#1 v1.5, key wrapping and key agreement are refused by name (E-1).',
        ];
        yield 'row 12, a ReferenceList' => [
            'reference-list-inside-key-refused.xml',
            MalformedEncryption::class,
            $otherChild,
        ];
        yield 'row 12, a CarriedKeyName' => ['carried-key-name-refused.xml', MalformedEncryption::class, $otherChild];
        yield 'row 18, a cipher value of 255 bytes' => [
            'key-cipher-value-255-bytes-refused.xml',
            LimitExceeded::class,
            $bound,
        ];
        yield 'row 18, a cipher value of 1025 bytes' => [
            'key-cipher-value-1025-bytes-refused.xml',
            LimitExceeded::class,
            $bound,
        ];
        yield 'an EncryptionMethod without Algorithm' => [
            'key-method-without-algorithm-refused.xml',
            MalformedEncryption::class,
            'An EncryptionMethod names its Algorithm (E-5).',
        ];
        yield 'no CipherData' => [
            'key-without-cipher-data-refused.xml',
            MalformedEncryption::class,
            'An EncryptedKey holds exactly one CipherData (E-5).',
        ];
        yield 'two KeyInfo' => [
            'two-key-infos-in-the-key-refused.xml',
            MalformedEncryption::class,
            'An EncryptedKey holds at most one KeyInfo (E-5).',
        ];
    }

    /**
     * E-5
     */
    #[Test]
    public function itRefusesAKeyWithoutEncryptionMethod(): void
    {
        // Given
        $bytes = preg_replace(
            '~      <xenc:EncryptionMethod Algorithm="[^"]*"/>\n~',
            '',
            Fixtures::bytes('vectors/response-encrypted-assertion-aes256-gcm.xml'),
        );
        static::assertNotNull($bytes);
        $document = Loaded::document($bytes);
        $element = Encrypted::keyOf($document);

        // Then
        $this->expectException(MalformedEncryption::class);
        $this->expectExceptionMessageIs('An EncryptedKey holds exactly one EncryptionMethod (E-5).');

        // When
        EncryptedKey::of($element);
    }

    /**
     * §9.2 row 35, Core I-4
     */
    #[Test]
    public function itRefusesAnElementOfAForeignDocument(): void
    {
        // Given
        $root = Foreign::parse('<xenc:EncryptedKey xmlns:xenc="' . Names::XMLENC . '"/>')->documentElement;
        static::assertNotNull($root);

        // Then
        $this->expectException(ForeignNode::class);

        // When
        EncryptedKey::of($root);
    }

    /**
     * §9.2 row 35, E-5
     */
    #[Test]
    public function itRefusesAnElementThatIsNotAnEncryptedKey(): void
    {
        // Given
        $bytes = preg_replace(
            ['~<xenc:EncryptedKey\b~', '~</xenc:EncryptedKey>~'],
            ['<xenc:EncryptedKeys', '</xenc:EncryptedKeys>'],
            Fixtures::bytes('vectors/response-encrypted-assertion-aes256-gcm.xml'),
        );
        static::assertNotNull($bytes);
        $document = Loaded::document($bytes);
        $keyInfo = Children::one(Encrypted::dataOf($document), new Name(Names::DSIG, 'KeyInfo'));
        $element = Children::one($keyInfo, new Name(Names::XMLENC, 'EncryptedKeys'));

        // Then
        $this->expectException(MalformedEncryption::class);
        $this->expectExceptionMessageIs('The element is not an xenc:EncryptedKey (E-5).');

        // When
        EncryptedKey::of($element);
    }

    /**
     * §9.2 row 37, E-13
     */
    #[Test]
    #[TestWith(
        [4097, 'A CipherValue is longer than maxEncryptedKeyTextBytes, 4096 bytes of text (E-13).'],
        'over the bound',
    )]
    #[TestWith(
        [4096, 'The cipher value of an EncryptedKey is not between 256 and maxEncryptedKeyBytes, 1024 bytes (E-13).'],
        'at the bound',
    )]
    public function itBoundsTheTextOfTheKeyBeforeDecodingIt(int $length, string $message): void
    {
        // Given
        $bytes = preg_replace(
            '~(<xenc:EncryptedKey\b.*?<xenc:CipherValue>)[^<]*(</xenc:CipherValue>)~s',
            '${1}' . str_repeat('A', $length) . '${2}',
            Fixtures::bytes('vectors/response-encrypted-assertion-aes256-gcm.xml'),
            1,
        );
        static::assertNotNull($bytes);
        $document = Loaded::document($bytes);
        $element = Encrypted::keyOf($document);

        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs($message);

        // When
        EncryptedKey::of($element);
    }
}
