<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Dsig\Unit;

use Throwable;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Exception\DuplicateId;
use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Dsig\Exception\AlgorithmUnavailable;
use Beffroi\Xml\Dsig\Exception\DigestMismatch;
use Beffroi\Xml\Dsig\Exception\LimitExceeded;
use Beffroi\Xml\Dsig\Exception\MalformedSignature;
use Beffroi\Xml\Dsig\Exception\SignatureMismatch;
use Beffroi\Xml\Dsig\Exception\WrongReference;
use Beffroi\Xml\Dsig\PrivateKey;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use Beffroi\Xml\Dsig\VerificationKey;
use Beffroi\Xml\Dsig\VerificationKeys;
use Beffroi\Xml\Dsig\Verifier;
use Beffroi\Xml\Tests\Core\Support\Foreign;
use Beffroi\Xml\Tests\Core\Support\Stack;
use Beffroi\Xml\Tests\Dsig\Support\Fixtures;
use Beffroi\Xml\Tests\Dsig\Support\Loaded;
use function defined;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use function str_starts_with;

/**
 * Section 6.1, D-1 to D-10, section 9.1, section 9.2
 */
final class VerifierTest extends TestCase
{
    private const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    private const string REDIRECT_QUERY = 'SAMLRequest=fZJNT8MwDIbv%2BRVR7m3SbhOIaJ2QEBISHIBx4BZrs&RelayState=%2Fhome&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256';

    private Verifier $verifier;

    private VerificationKeys $trusted;

    protected function setUp(): void
    {
        $this->verifier = new Verifier(new Loader(Stack::idAttributes()));
        $this->trusted = new VerificationKeys([$this->key('test-signing-certificate.pem')]);
    }

    /**
     * §9.1, §9.3 row 1, D-10
     */
    #[Test]
    #[DataProvider('provideVectors')]
    public function itVerifiesAVector(string $fixture, string $id, string $root, SignatureAlgorithm $algorithm): void
    {
        // Given
        $document = Loaded::fixture('vectors/' . $fixture);
        $signed = $document->elementById($id);

        // When
        $verified = $this->verifier->verify($signed, $this->trusted);

        // Then
        static::assertSame($root, $verified->document->root()->localName);
        static::assertSame($id, $verified->document->root()->getAttribute('ID'));
        static::assertSame([], Children::named($verified->document->root(), new Name(self::DSIG, 'Signature')));
        static::assertSame($algorithm, $verified->algorithm);
        static::assertSame($this->trusted->keys[0], $verified->key);
        static::assertTrue(str_starts_with($verified->canonical->bytes, '<' . $verified->document->root()->tagName));
    }

    /**
     * @return iterable<string, array{string, string, string, SignatureAlgorithm}>
     */
    public static function provideVectors(): iterable
    {
        yield 'rsa-sha256' => [
            'response-assertion-rsa-sha256.xml',
            '_assertion-d4e5f6',
            'Assertion',
            SignatureAlgorithm::RsaSha256,
        ];
        yield 'rsa-sha384' => [
            'response-assertion-rsa-sha384.xml',
            '_assertion-d4e5f6',
            'Assertion',
            SignatureAlgorithm::RsaSha384,
        ];
        yield 'rsa-sha512' => [
            'response-assertion-rsa-sha512.xml',
            '_assertion-d4e5f6',
            'Assertion',
            SignatureAlgorithm::RsaSha512,
        ];
        yield 'exclusive with comments, a comment inside the signed text' => [
            'response-assertion-with-comments.xml',
            '_assertion-d4e5f6',
            'Assertion',
            SignatureAlgorithm::RsaSha256,
        ];
        yield 'a PrefixList on the transform' => [
            'response-assertion-prefixlist.xml',
            '_assertion-d4e5f6',
            'Assertion',
            SignatureAlgorithm::RsaSha256,
        ];
        yield 'an entity descriptor, the Signature first' => [
            'entity-descriptor-rsa-sha256.xml',
            '_entity-m1n2o3',
            'EntityDescriptor',
            SignatureAlgorithm::RsaSha256,
        ];
        yield 'the assertion of a doubly signed response' => [
            'response-and-assertion-both-signed.xml',
            '_assertion-d4e5f6',
            'Assertion',
            SignatureAlgorithm::RsaSha256,
        ];
        yield 'the response of a doubly signed response' => [
            'response-and-assertion-both-signed.xml',
            '_response-a1b2c3',
            'Response',
            SignatureAlgorithm::RsaSha256,
        ];
        if (defined('OPENSSL_PKCS1_PSS_PADDING')) {
            yield 'RSASSA-PSS with SHA-256' => [
                'response-assertion-rsa-pss-sha256.xml',
                '_assertion-d4e5f6',
                'Assertion',
                SignatureAlgorithm::RsaPssSha256,
            ];
            yield 'RSASSA-PSS with SHA-384' => [
                'response-assertion-rsa-pss-sha384.xml',
                '_assertion-d4e5f6',
                'Assertion',
                SignatureAlgorithm::RsaPssSha384,
            ];
            yield 'RSASSA-PSS with SHA-512' => [
                'response-assertion-rsa-pss-sha512.xml',
                '_assertion-d4e5f6',
                'Assertion',
                SignatureAlgorithm::RsaPssSha512,
            ];
        }
    }

    /**
     * §9.1, section 6.1 step 8, XML Signature 1.1 §4.4.3.3
     */
    #[Test]
    public function itsCanonicalBytesOmitTheCommentsWhateverTheTransformSays(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-assertion-with-comments.xml');

        // When
        $verified = $this->verifier->verify($document->elementById('_assertion-d4e5f6'), $this->trusted);

        // Then
        static::assertStringNotContainsString('<!--', $verified->canonical->bytes);
        static::assertStringContainsString('>user-0001<', $verified->canonical->bytes);
    }

    /**
     * §9.1, D-10
     */
    #[Test]
    public function itsCanonicalBytesOfAResponseHoldTheAssertionsSignature(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-and-assertion-both-signed.xml');

        // When
        $verified = $this->verifier->verify($document->elementById('_response-a1b2c3'), $this->trusted);

        // Then
        static::assertStringContainsString('<ds:Signature', $verified->canonical->bytes);
        static::assertCount(
            1,
            Children::named(
                Children::one($verified->document->root(), new Name(Stack::SAML_ASSERTION, 'Assertion')),
                new Name(self::DSIG, 'Signature'),
            ),
        );
    }

    /**
     * §9.1, section 13
     */
    #[Test]
    public function itRefusesPssWhereTheBuildCannotVerifyIt(): void
    {
        // Given
        if (SignatureAlgorithm::RsaPssSha256->isAvailable()) {
            static::markTestSkipped('RSASSA-PSS is available on this build; the refusal is the business of PHP 8.4 and of OpenSSL before 3.1.');
        }
        $document = Loaded::fixture('vectors/response-assertion-rsa-pss-sha256.xml');
        $signed = $document->elementById('_assertion-d4e5f6');

        // Then
        $this->expectException(AlgorithmUnavailable::class);
        $this->expectExceptionMessageIs('This build cannot verify RSASSA-PSS: it needs PHP 8.5 and OpenSSL 3.1 (section 13).');

        // When
        $this->verifier->verify($signed, $this->trusted);
    }

    /**
     * §9.3 row 2, D-7
     */
    #[Test]
    public function itVerifiesWithTheSecondKeyWhenTheFirstIsAStranger(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-assertion-rsa-sha256.xml');
        $stranger = $this->key('stranger-certificate.pem');
        $right = $this->key('test-signing-certificate.pem');

        // When
        $verified = $this->verifier->verify(
            $document->elementById('_assertion-d4e5f6'),
            new VerificationKeys([$stranger, $right]),
        );

        // Then
        static::assertSame($right, $verified->key);
    }

    /**
     * §9.3 row 2, D-7
     */
    #[Test]
    public function itRefusesWhenNoTrustedKeyVerifies(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-assertion-rsa-sha256.xml');
        $signed = $document->elementById('_assertion-d4e5f6');

        // Then
        $this->expectException(SignatureMismatch::class);
        $this->expectExceptionMessageIs('No trusted key verifies the signature over SignedInfo (D-7, D-8).');

        // When
        $this->verifier->verify($signed, new VerificationKeys([$this->key('stranger-certificate.pem')]));
    }

    /**
     * §9.3 row 3, D-1, D-10
     */
    #[Test]
    public function itReadsNothingOfTheDocumentButTheClaimedElementAndItsSignature(): void
    {
        // Given
        $document = Loaded::fixture('behaviour/unsigned-assertion-elsewhere-verifies.xml');
        $signed = $document->elementById('_assertion-d4e5f6');

        // When
        $verified = $this->verifier->verify($signed, $this->trusted);

        // Then
        static::assertSame('_assertion-d4e5f6', $verified->document->root()->getAttribute('ID'));
        static::assertStringNotContainsString('attacker', $verified->canonical->bytes);
        static::assertCount(1, Children::named($signed, new Name(self::DSIG, 'Signature')));
        static::assertTrue($document->hasId('_other-x1y2z3'));
    }

    /**
     * §9.2 row 13, D-8
     */
    #[Test]
    public function itVerifiesADigestValueSplitByAComment(): void
    {
        // Given
        $document = Loaded::fixture('behaviour/digest-value-comment-split-loads.xml');

        // When
        $verified = $this->verifier->verify($document->elementById('_assertion-d4e5f6'), $this->trusted);

        // Then
        static::assertSame('Assertion', $verified->document->root()->localName);
    }

    /**
     * §9.2 row 1, Core I-8
     */
    #[Test]
    public function itsLoaderRefusesTheWrappingThatDuplicatesTheId(): void
    {
        // Given
        $bytes = Fixtures::bytes('hostile/xsw-assertion-in-extensions-same-id-refused.xml');

        // Then
        $this->expectException(DuplicateId::class);
        $this->expectExceptionMessageIs('An ID value appears twice in the document (I-8).');

        // When
        Loaded::document($bytes);
    }

    /**
     * §9.2 rows 2, 4, 5, 6, 14, 15, 16, 17, 37 and 38, D-1, D-2, D-7, D-8
     *
     * @param class-string<Throwable> $exception
     */
    #[Test]
    #[DataProvider('provideRefusedVariants')]
    public function itRefusesAWrappingOrAMismatch(string $fixture, string $id, string $exception, string $message): void
    {
        // Given
        $document = Loaded::fixture('hostile/' . $fixture);
        $signed = $document->elementById($id);

        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($message);

        // When
        $this->verifier->verify($signed, $this->trusted);
    }

    /**
     * @return iterable<string, array{string, string, class-string<Throwable>, string}>
     */
    public static function provideRefusedVariants(): iterable
    {
        $mismatch = 'No trusted key verifies the signature over SignedInfo (D-7, D-8).';
        $d1 = 'The claimed element holds exactly one ds:Signature, a direct child (D-1).';

        yield 'row 2, the signed assertion wrapped, the unsigned one claimed with the copied Signature' => [
            'xsw-assertion-in-extensions-new-id-refused.xml',
            '_evil-e1f2g3',
            WrongReference::class,
            'The reference does not name the claimed element (D-2).',
        ];
        yield 'row 4, the Signature moved to the response' => [
            'xsw-signature-moved-to-response-refused.xml',
            '_assertion-d4e5f6',
            MalformedSignature::class,
            $d1,
        ];
        yield 'row 5, the Signature a grandchild' => [
            'xsw-signature-grandchild-refused.xml',
            '_assertion-d4e5f6',
            MalformedSignature::class,
            $d1,
        ];
        yield 'row 6, two Signature children' => [
            'xsw-two-signatures-refused.xml',
            '_assertion-d4e5f6',
            MalformedSignature::class,
            $d1,
        ];
        yield 'row 14, a DigestValue altered' => [
            'digest-value-altered-refused.xml',
            '_assertion-d4e5f6',
            SignatureMismatch::class,
            $mismatch,
        ];
        yield 'row 15, a SignatureValue altered' => [
            'signature-value-altered-refused.xml',
            '_assertion-d4e5f6',
            SignatureMismatch::class,
            $mismatch,
        ];
        yield 'row 16, the signed element altered' => [
            'signed-element-altered-refused.xml',
            '_assertion-d4e5f6',
            DigestMismatch::class,
            'The claimed element is not what was signed (D-8).',
        ];
        yield 'row 17, re-signed with a stranger key, its certificate in KeyInfo' => [
            'resigned-with-a-stranger-key-refused.xml',
            '_assertion-d4e5f6',
            SignatureMismatch::class,
            $mismatch,
        ];
        yield 'row 37, a PSS signature claimed as PKCS#1 v1.5' => [
            'pss-signature-claimed-as-pkcs1-refused.xml',
            '_assertion-d4e5f6',
            SignatureMismatch::class,
            $mismatch,
        ];
        yield 'row 38, a SHA-256 signature claimed as SHA-512' => [
            'sha256-signature-claimed-as-sha512-refused.xml',
            '_assertion-d4e5f6',
            SignatureMismatch::class,
            $mismatch,
        ];
    }

    /**
     * §9.2 row 37, D-8
     */
    #[Test]
    public function itRefusesAPkcs1SignatureClaimedAsPss(): void
    {
        // Given
        $document = Loaded::fixture('hostile/pkcs1-signature-claimed-as-pss-refused.xml');
        $signed = $document->elementById('_assertion-d4e5f6');

        // Then
        $this->expectException(
            defined('OPENSSL_PKCS1_PSS_PADDING') ? SignatureMismatch::class : AlgorithmUnavailable::class,
        );

        // When
        $this->verifier->verify($signed, $this->trusted);
    }

    /**
     * §9.2 row 40, Core I-4
     */
    #[Test]
    public function itRefusesAnElementOfAForeignDocument(): void
    {
        // Given
        $root = Foreign::parse(Fixtures::bytes('vectors/response-assertion-rsa-sha256.xml'))->documentElement;
        static::assertNotNull($root);

        // Then
        $this->expectException(ForeignNode::class);

        // When
        $this->verifier->verify($root, $this->trusted);
    }

    /**
     * Section 6.1 step 6
     */
    #[Test]
    public function itVerifiesAPssSignatureWhateverTheLengthOfItsSalt(): void
    {
        // Given
        if (! SignatureAlgorithm::RsaPssSha256->isAvailable()) {
            static::markTestSkipped('RSASSA-PSS is not available on this build.');
        }
        $document = Loaded::fixture('behaviour/pss-salt-zero-verifies.xml');

        // When
        $verified = $this->verifier->verify($document->elementById('_assertion-d4e5f6'), $this->trusted);

        // Then
        static::assertSame(SignatureAlgorithm::RsaPssSha256, $verified->algorithm);
    }

    /**
     * §9.3 row 21, section 6.4
     */
    #[Test]
    #[DataProvider('provideDetachedSchemes')]
    public function itVerifiesADetachedSignature(SignatureAlgorithm $algorithm): void
    {
        // Given
        $bytes = self::REDIRECT_QUERY;
        $signature = PrivateKey::fromPem(Fixtures::bytes('keys/test-signing-key.pem'))->sign($bytes, $algorithm);
        $keys = new VerificationKeys([
            $this->key('stranger-certificate.pem'),
            $this->key('test-signing-certificate.pem'),
        ]);

        // When
        $key = $this->verifier->verifyDetached($bytes, $signature, $algorithm, $keys);

        // Then
        static::assertSame($keys->keys[1], $key);
    }

    /**
     * @return iterable<string, array{SignatureAlgorithm}>
     */
    public static function provideDetachedSchemes(): iterable
    {
        foreach (SignatureAlgorithm::cases() as $algorithm) {
            if (! $algorithm->isAvailable()) {
                continue;
            }

            yield $algorithm->name => [$algorithm];
        }
    }

    /**
     * §9.3 row 22, section 6.4, D-8, D-14
     *
     * @param class-string<Throwable> $exception
     */
    #[Test]
    #[DataProvider('provideRefusedDetachedSignatures')]
    public function itRefusesADetachedSignature(
        string $bytes,
        ?int $length,
        string $trusted,
        string $exception,
        string $message,
    ): void {
        // Given
        $signature = $length === null
            ? PrivateKey::fromPem(Fixtures::bytes('keys/test-signing-key.pem'))->sign(
                self::REDIRECT_QUERY,
                SignatureAlgorithm::RsaSha256,
            )
            : str_repeat("\x01", $length);
        $keys = new VerificationKeys([$this->key($trusted)]);

        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($message);

        // When
        $this->verifier->verifyDetached($bytes, $signature, SignatureAlgorithm::RsaSha256, $keys);
    }

    /**
     * @return iterable<string, array{string, ?int, string, class-string<Throwable>, string}>
     */
    public static function provideRefusedDetachedSignatures(): iterable
    {
        $mismatch = 'No trusted key verifies the detached signature (D-7, D-8).';
        $bound = 'A signature is not between 256 and maxSignatureValueBytes, 1024 bytes (D-14).';
        $test = 'test-signing-certificate.pem';

        yield 'other bytes' => [self::REDIRECT_QUERY . '&x', null, $test, SignatureMismatch::class, $mismatch];
        yield 'a key the consumer does not trust' => [
            self::REDIRECT_QUERY,
            null,
            'stranger-certificate.pem',
            SignatureMismatch::class,
            $mismatch,
        ];
        yield 'at the bound, 1 024 bytes' => [self::REDIRECT_QUERY, 1024, $test, SignatureMismatch::class, $mismatch];
        yield 'one byte under the floor, 255 bytes' => [self::REDIRECT_QUERY, 255, $test, LimitExceeded::class, $bound];
        yield 'one byte over the bound, 1 025 bytes' => [
            self::REDIRECT_QUERY,
            1025,
            $test,
            LimitExceeded::class,
            $bound,
        ];
    }

    /**
     * §9.3 row 22, section 13
     */
    #[Test]
    public function itRefusesADetachedPssSignatureWhereTheBuildCannotVerifyIt(): void
    {
        // Given
        if (SignatureAlgorithm::RsaPssSha256->isAvailable()) {
            static::markTestSkipped('RSASSA-PSS is available on this build; the refusal is the business of PHP 8.4 and of OpenSSL before 3.1.');
        }

        // Then
        $this->expectException(AlgorithmUnavailable::class);
        $this->expectExceptionMessageIs('This build cannot verify RSASSA-PSS: it needs PHP 8.5 and OpenSSL 3.1 (section 13).');

        // When
        $this->verifier->verifyDetached(
            self::REDIRECT_QUERY,
            str_repeat("\x01", 256),
            SignatureAlgorithm::RsaPssSha256,
            $this->trusted,
        );
    }

    private function key(string $file): VerificationKey
    {
        return VerificationKey::fromCertificatePem(Fixtures::bytes('keys/' . $file));
    }
}
