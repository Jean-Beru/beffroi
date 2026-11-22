<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Unit;

use function array_map;
use function array_unique;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\MissingChild;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Text;
use Beffroi\Xml\Enc\Decryptor;
use Beffroi\Xml\Enc\Exception\CoveringSignatureRequired;
use Beffroi\Xml\Enc\Exception\DecryptionFailed;
use Beffroi\Xml\Enc\PlaintextReaderInterface;
use Beffroi\Xml\Enc\PrivateDecryptionKey;
use Beffroi\Xml\Tests\Core\Support\Stack;
use Beffroi\Xml\Tests\Enc\Support\CoveringDocument;
use Beffroi\Xml\Tests\Enc\Support\Encrypted;
use Beffroi\Xml\Tests\Enc\Support\Fixtures;
use Beffroi\Xml\Tests\Enc\Support\LoadedDocument;
use Beffroi\Xml\Tests\Enc\Support\RefusingReader;
use Beffroi\Xml\Tests\Enc\Support\IssuerReader;
use Beffroi\Xml\Tests\Enc\Support\Loaded;
use Beffroi\Xml\Tests\Enc\Support\UnwrappingKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function serialize;
use function str_repeat;

/**
 * Section 6.1, E-15, E-16, section 6.1 step 9
 */
final class DecryptorCoveredTest extends TestCase
{
    /**
     * §9.1 rows 8 and 9, E-1, E-15, section 5.1
     */
    #[Test]
    #[DataProvider('provideCbcVectors')]
    public function itDecryptsAesCbcUnderASignatureThatCoversIt(string $fixture): void
    {
        // Given
        $document = Loaded::fixture('vectors/' . $fixture);

        // When
        $decrypted = $this->decryptor()->decryptCovered(
            Encrypted::dataOf($document),
            $this->key(),
            new CoveringDocument($document),
            new LoadedDocument(),
        );

        // Then
        $root = $decrypted->root();
        static::assertTrue(new Name(Stack::SAML_ASSERTION, 'Assertion')->matches($root));
        static::assertSame($root, $decrypted->elementById('_assertion-d4e5f6'));
        static::assertSame('https://idp.example.org', self::issuerOf($decrypted));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideCbcVectors(): iterable
    {
        yield 'row 8, aes128-cbc' => ['response-encrypted-assertion-aes128-cbc.xml'];
        yield 'row 9, aes256-cbc under rsa-oaep-mgf1p and its DigestMethod of SHA-1' => [
            'response-encrypted-assertion-aes256-cbc-mgf1p-digest-sha1.xml',
        ];
    }

    /**
     * §9.2 row 42, E-15
     */
    #[Test]
    #[DataProvider('provideCbcVectors')]
    public function itRefusesAesCbcWithoutASignatureBeforeTouchingTheKey(string $fixture): void
    {
        // Given
        $document = Loaded::fixture('vectors/' . $fixture);
        $element = Encrypted::dataOf($document);
        $port = new UnwrappingKey(str_repeat("\x00", 32));

        // When
        try {
            $this->decryptor()->decrypt($element, $port);
            static::fail('The decryptor opened AES-CBC without a signature.');
        } catch (CoveringSignatureRequired $refusal) {
            // Then
            static::assertSame(
                [
                    'AES-CBC is decrypted only under a verified signature that covers the encrypted element (E-15).',
                    null,
                ],
                [$refusal->getMessage(), $port->wrapped],
            );
        }
    }

    /**
     * §9.2 row 43, E-15
     */
    #[Test]
    #[DataProvider('provideVectorsOfBothModes')]
    public function itRefusesASignatureThatCoversAnotherDocument(string $fixture): void
    {
        // Given
        $document = Loaded::fixture('vectors/' . $fixture);
        $element = Encrypted::dataOf($document);
        $another = new CoveringDocument(Loaded::fixture('vectors/' . $fixture));
        $port = new UnwrappingKey(str_repeat("\x00", 32));

        // When
        try {
            $this->decryptor()->decryptCovered($element, $port, $another, new LoadedDocument());
            static::fail('The decryptor took a signature of another document.');
        } catch (CoveringSignatureRequired $refusal) {
            // Then
            static::assertSame(
                ['The encrypted element is not a node of the document the signature covers (E-15).', null],
                [$refusal->getMessage(), $port->wrapped],
            );
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideVectorsOfBothModes(): iterable
    {
        yield 'aes256-gcm' => ['response-encrypted-assertion-aes256-gcm.xml'];
        yield 'aes128-cbc' => ['response-encrypted-assertion-aes128-cbc.xml'];
    }

    /**
     * §9.3 row 26, E-15
     */
    #[Test]
    public function itDecryptsAesGcmUnderASignatureAsWithoutOne(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-encrypted-assertion-aes256-gcm.xml');
        $element = Encrypted::dataOf($document);
        $expected = $this->decryptor()->decrypt($element, $this->key());

        // When
        $decrypted = $this->decryptor()->decryptCovered($element, $this->key(), new CoveringDocument($document), new LoadedDocument());

        // Then
        static::assertSame(self::issuerOf($expected), self::issuerOf($decrypted));
        static::assertTrue($decrypted->hasId('_assertion-d4e5f6'));
    }

    /**
     * §9.2 rows 45 to 48, E-2, E-16
     */
    #[Test]
    #[DataProvider('provideFailingCbcFixtures')]
    public function itFailsInTheOneWayUnderAesCbc(string $fixture): void
    {
        // Given
        $document = Loaded::fixture('hostile/' . $fixture);
        $element = Encrypted::dataOf($document);

        // Then
        $this->expectException(DecryptionFailed::class);
        $this->expectExceptionMessageIs('The data could not be decrypted (E-3).');

        // When
        $this->decryptor()->decryptCovered($element, $this->key(), new CoveringDocument($document), new LoadedDocument());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideFailingCbcFixtures(): iterable
    {
        yield 'row 45, a 32-byte session key under aes128-cbc, which the primitive would have cut and used' => [
            'cbc-session-key-32-bytes-declared-aes128-cbc-refused.xml',
        ];
        yield 'row 46, a count of 0' => ['cbc-padding-count-zero-refused.xml'];
        yield 'row 46, a count of 17' => ['cbc-padding-count-seventeen-refused.xml'];
        yield 'row 47, the octet that sets the count altered' => ['cbc-padding-octet-altered-refused.xml'];
        yield 'row 47, the first block garbled, the count in range' => [
            'cbc-ciphertext-first-block-altered-refused.xml',
        ];
        yield 'row 47, the key wrapped under the stranger\'s certificate' => [
            'cbc-key-wrapped-under-the-stranger-certificate-refused.xml',
        ];
        yield 'row 48, an authentic plaintext holding a DOCTYPE' => ['cbc-plaintext-with-doctype-refused.xml'];
        yield 'row 48, an authentic plaintext that is not XML' => ['cbc-plaintext-not-xml-refused.xml'];
    }

    /**
     * §9.3 rows 21 and 22, E-16
     */
    #[Test]
    #[DataProvider('providePaddings')]
    public function itReadsTheCountOfThePaddingAndNothingElse(string $fixture): void
    {
        // Given
        $document = Loaded::fixture($fixture);

        // When
        $decrypted = $this->decryptor()->decryptCovered(
            Encrypted::dataOf($document),
            $this->key(),
            new CoveringDocument($document),
            new LoadedDocument(),
        );

        // Then
        static::assertSame('https://idp.example.org', self::issuerOf($decrypted));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function providePaddings(): iterable
    {
        yield 'row 21, a count of 1' => ['behaviour/cbc-padding-count-one-decrypts.xml'];
        yield 'row 21, a count of 16, a whole block' => ['behaviour/cbc-padding-of-a-whole-block-decrypts.xml'];
        yield 'row 22, the random octets of xmlsec1' => ['vectors/response-encrypted-assertion-aes128-cbc.xml'];
    }

    /**
     * §9.2 row 49, E-15, section 6.1 step 1
     */
    #[Test]
    #[DataProvider('provideVectorsOfBothModes')]
    public function itRefusesAnElementTheRootOfTheCoveredDocumentDoesNotContain(string $fixture): void
    {
        // Given
        $document = Loaded::fixture('vectors/' . $fixture);
        $element = Encrypted::dataOf($document);
        $element->remove();
        $port = new UnwrappingKey(str_repeat("\x00", 32));

        // When
        try {
            $this->decryptor()->decryptCovered($element, $port, new CoveringDocument($document), new LoadedDocument());
            static::fail('The decryptor took an element its covered root does not contain.');
        } catch (CoveringSignatureRequired $refusal) {
            // Then
            static::assertSame(
                ['The encrypted element is not a node of the document the signature covers (E-15).', null],
                [$refusal->getMessage(), $port->wrapped],
            );
        }
    }

    /**
     * §9.2 row 50, E-16
     */
    #[Test]
    public function itRefusesWhatTheReaderRefusesUnderAesCbcAsTheOneFailure(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-encrypted-assertion-aes128-cbc.xml');
        $reader = new RefusingReader();

        // When
        try {
            $this->decryptor()->decryptCovered(
                Encrypted::dataOf($document),
                $this->key(),
                new CoveringDocument($document),
                $reader,
            );
            static::fail('The decryptor let a refusal of the reader through under AES-CBC.');
        } catch (DecryptionFailed $failure) {
            // Then
            static::assertSame([DecryptionFailed::MESSAGE, true], [$failure->getMessage(), $reader->asked]);
        }
    }

    /**
     * §9.2 row 50, E-4
     */
    #[Test]
    public function itLetsWhatTheReaderRefusesUnderAesGcmThroughAsItIs(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-encrypted-assertion-aes256-gcm.xml');

        // Then
        $this->expectException(MissingChild::class);
        $this->expectExceptionMessageIs('The consumer refuses what the plaintext holds (E-16).');

        // When
        $this->decryptor()->decryptCovered(
            Encrypted::dataOf($document),
            $this->key(),
            new CoveringDocument($document),
            new RefusingReader(),
        );
    }

    /**
     * §9.3 row 27, E-16
     */
    #[Test]
    #[DataProvider('provideVectorsOfBothModes')]
    public function itReturnsWhatTheReaderRead(string $fixture): void
    {
        // Given
        $document = Loaded::fixture('vectors/' . $fixture);
        $reader = new IssuerReader();

        // When
        $issuer = $this->decryptor()->decryptCovered(
            Encrypted::dataOf($document),
            $this->key(),
            new CoveringDocument($document),
            $reader,
        );

        // Then
        static::assertSame('https://idp.example.org', $issuer);
    }

    /**
     * §9.2 row 33, E-3, E-16, section 6.1 step 9
     */
    #[Test]
    public function itRaisesEveryFailureFromOnePlace(): void
    {
        // Given
        $reads = new LoadedDocument();
        $covered = [
            ['hostile/cbc-key-wrapped-under-the-stranger-certificate-refused.xml', $reads],
            ['hostile/cbc-session-key-32-bytes-declared-aes128-cbc-refused.xml', $reads],
            ['hostile/cbc-padding-count-zero-refused.xml', $reads],
            ['hostile/cbc-padding-count-seventeen-refused.xml', $reads],
            ['hostile/cbc-padding-octet-altered-refused.xml', $reads],
            ['hostile/cbc-ciphertext-first-block-altered-refused.xml', $reads],
            ['hostile/cbc-plaintext-with-doctype-refused.xml', $reads],
            ['hostile/cbc-plaintext-not-xml-refused.xml', $reads],
            ['vectors/response-encrypted-assertion-aes128-cbc.xml', new RefusingReader()],
            ['hostile/encrypted-under-the-stranger-certificate-refused.xml', $reads],
            ['hostile/tag-altered-refused.xml', $reads],
            ['hostile/ciphertext-altered-refused.xml', $reads],
        ];
        $uncovered = [
            'hostile/encrypted-under-the-stranger-certificate-refused.xml',
            'hostile/session-key-32-bytes-declared-aes128-gcm-refused.xml',
            'hostile/tag-truncated-refused.xml',
            'hostile/ciphertext-altered-refused.xml',
        ];

        // When
        $underSignature = array_map(
            fn (array $case): DecryptionFailed => $this->failToDecrypt($case[0], true, $case[1]),
            $covered,
        );
        $withoutSignature = array_map(fn (string $fixture): DecryptionFailed => $this->failToDecrypt($fixture, false), $uncovered);

        // Then
        $places = array_map(
            static fn (DecryptionFailed $failure): array => [$failure::class, $failure->getMessage(), $failure->getFile(), $failure->getLine()],
            [...$underSignature, ...$withoutSignature],
        );
        static::assertCount(1, array_unique(array_map(serialize(...), $places)));
        static::assertCount(1, array_unique(array_map(self::frames(...), $underSignature)));
        static::assertCount(1, array_unique(array_map(self::frames(...), $withoutSignature)));
    }

    /**
     * @param PlaintextReaderInterface<mixed> $reader
     */
    private function failToDecrypt(
        string $fixture,
        bool $covered,
        PlaintextReaderInterface $reader = new LoadedDocument(),
    ): DecryptionFailed {
        $document = Loaded::fixture($fixture);
        $element = Encrypted::dataOf($document);
        try {
            if ($covered) {
                $this->decryptor()->decryptCovered($element, $this->key(), new CoveringDocument($document), $reader);
            } else {
                $this->decryptor()->decrypt($element, $this->key());
            }
        } catch (DecryptionFailed $failure) {
            return $failure;
        }

        static::fail('The decryptor accepted ' . $fixture);
    }

    private static function frames(DecryptionFailed $failure): string
    {
        return serialize(array_map(
            static fn (array $frame): array => [
                $frame['file'] ?? null,
                $frame['line'] ?? null,
                $frame['class'] ?? null,
                $frame['function'],
            ],
            $failure->getTrace(),
        ));
    }

    private function decryptor(): Decryptor
    {
        return new Decryptor(new Loader(Stack::idAttributes()));
    }

    private function key(): PrivateDecryptionKey
    {
        return PrivateDecryptionKey::fromPem(Fixtures::bytes('keys/test-signing-key.pem'));
    }

    private static function issuerOf(Document $document): string
    {
        return Text::of(Children::one($document->root(), new Name(Stack::SAML_ASSERTION, 'Issuer')));
    }
}
