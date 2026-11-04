<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Validation;

use Beffroi\Saml2\Model\Exception\InResponseToMismatch;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\MessageRefused;
use Beffroi\Saml2\Model\Exception\Replayed;
use Beffroi\Saml2\Model\Exception\SignatureRequired;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Support\FrozenClock;
use Beffroi\Saml2\Model\Tests\Support\InMemoryReplayGuard;
use Beffroi\Saml2\Model\Tests\Support\RecordingDecryptionKey;
use Beffroi\Saml2\Model\Tests\Unit\Internal\Response\ResponseFixtures;
use Beffroi\Saml2\Model\Validation\ExpectedResponse;
use Beffroi\Saml2\Model\Validation\ResponseValidator;
use Beffroi\Saml2\Model\Validation\SignatureCoverage;
use Beffroi\Saml2\Model\Validation\TimeBounds;
use Beffroi\Xml\Dsig\Exception\DigestMismatch;
use Beffroi\Xml\Enc\DecryptionKeyInterface;
use Beffroi\Xml\Enc\Exception\CoveringSignatureRequired;
use Beffroi\Xml\Enc\Exception\DecryptionFailed;
use Beffroi\Xml\Enc\Exception\MalformedEncryption;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 6.7, section 6.1 steps 2 to 6, M-1, M-2, M-4, M-8, M-11, SAML Core §2.3.4, §6.2, enc.md E-3
 */
final class ResponseValidatorDecryptionTest extends TestCase
{
    use ResponseFixtures;

    /**
     * §9.3 row 23, section 6.7, M-1
     */
    #[Test]
    public function itReadsAnEncryptedAssertionAsTheSameAssertionInClear(): void
    {
        // Given
        $clear = $this->validator()->validate(
            $this->unverified('behaviour/response-signed-assertion-accepted.xml'),
            self::identityProvider(),
            self::expected(),
        );
        $response = $this->unverified('encrypted/response-encrypted-signed-assertion-accepted.xml');

        // When
        $accepted = $this->validator()->validate($response, self::identityProvider()->withDecryptionKey(self::decryptionKey()), self::expected());

        // Then
        static::assertEquals(
            [$clear->responseId, $clear->assertion, $clear->coverage],
            [$accepted->responseId, $accepted->assertion, $accepted->coverage],
        );
    }

    /**
     * §9.3 row 26, M-18, section 6.1 step 14, saml.md S-67
     */
    #[Test]
    public function itSaysAnAssertionItDecryptedArrivedEncrypted(): void
    {
        // Given
        $response = $this->unverified('encrypted/response-encrypted-signed-assertion-accepted.xml');

        // When
        $accepted = $this->validator()->validate($response, self::identityProvider()->withDecryptionKey(self::decryptionKey()), self::expected());

        // Then
        static::assertTrue($accepted->encrypted);
    }

    /**
     * §9.3 row 26, M-18
     */
    #[Test]
    public function itSaysAnAssertionInClearArrivedInClear(): void
    {
        // Given
        $response = $this->unverified('behaviour/response-signed-assertion-accepted.xml');

        // When
        $accepted = $this->validator()->validate($response, self::identityProvider()->withDecryptionKey(self::decryptionKey()), self::expected());

        // Then
        static::assertFalse($accepted->encrypted);
    }

    /**
     * §9.3 row 24, M-1, M-2, section 6.7
     */
    #[Test]
    public function itReadsAnUnsignedAssertionWhoseCiphertextTheResponsesSignatureCovered(): void
    {
        // Given
        $response = $this->unverified('encrypted/response-signed-over-encrypted-assertion-accepted.xml');

        // When
        $accepted = $this->validator()->validate($response, self::identityProvider()->withDecryptionKey(self::decryptionKey()), self::expected());

        // Then
        static::assertSame(
            [SignatureCoverage::Response, '_response', '_assertion', '_7a2f4c1d9e'],
            [$accepted->coverage, $accepted->responseId, $accepted->assertion->id, $accepted->assertion->nameId->value],
        );
    }

    /**
     * §9.2 row 38, section 6.7, enc.md E-3
     *
     * @param 'idp'|'sp' $key
     */
    #[Test]
    #[DataProvider('provideCiphertextsTheKeyDoesNotOpen')]
    public function itRefusesWithOneErrorWhateverFailedInTheDecryption(string $fixture, string $key): void
    {
        // Given
        $response = $this->unverified($fixture);

        // Then
        $this->expectException(DecryptionFailed::class);
        $this->expectExceptionMessageIs('The data could not be decrypted (E-3).');

        // When
        $this->validator()->validate($response, self::identityProvider()->withDecryptionKey(self::decryptionKey($key)), self::expected());
    }

    /**
     * @return iterable<string, array{string, 'idp'|'sp'}>
     */
    public static function provideCiphertextsTheKeyDoesNotOpen(): iterable
    {
        yield 'a tampered ciphertext' => ['encrypted/response-encrypted-ciphertext-altered-refused.xml', 'sp'];
        yield 'a wrong key' => ['encrypted/response-encrypted-signed-assertion-accepted.xml', 'idp'];
        yield 'a truncated tag' => ['encrypted/response-encrypted-tag-truncated-refused.xml', 'sp'];
    }

    /**
     * §9.2 row 39, M-2, section 6.7, SAML Core §6.2
     */
    #[Test]
    public function itVerifiesTheSignatureOfTheResponseBeforeAnyDecryption(): void
    {
        // Given
        $response = $this->unverified('encrypted/response-signed-over-encrypted-assertion-ciphertext-altered-refused.xml');

        // Then
        $this->expectException(DigestMismatch::class);
        $this->expectExceptionMessageIs('The claimed element is not what was signed (D-8).');

        // When
        $this->validator()->validate($response, self::identityProvider()->withDecryptionKey(self::decryptionKey()), self::expected());
    }

    /**
     * §9.2 row 40, M-2, section 6.7
     */
    #[Test]
    public function itRefusesAnEncryptedAssertionNoSignatureCovers(): void
    {
        // Given
        $response = $this->unverified('encrypted/response-encrypted-unsigned-assertion-refused.xml');
        $message = 'Neither the response nor its assertion carries a ds:Signature, one of which the profile requires (M-2).';

        // Then
        $this->expectException(SignatureRequired::class);
        $this->expectExceptionMessageIs($message);

        // When
        $this->validator()->validate($response, self::identityProvider()->withDecryptionKey(self::decryptionKey()), self::expected());
    }

    /**
     * §9.2 row 41, M-4, section 6.7
     */
    #[Test]
    public function itRefusesAPlaintextThatIsNotAnAssertion(): void
    {
        // Given
        $response = $this->unverified('encrypted/response-encrypted-not-an-assertion-refused.xml');

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('The plaintext of the saml:EncryptedAssertion is not a saml:Assertion (M-4).');

        // When
        $this->validator()->validate($response, self::identityProvider()->withDecryptionKey(self::decryptionKey()), self::expected());
    }

    /**
     * §9.2 row 42, section 6.7, M-8, M-10, SAML Profiles §4.1.4.2 as corrected by E17
     *
     * @param class-string<MessageRefused> $exception
     */
    #[Test]
    #[DataProvider('provideEnvelopesRefusedBeforeTheKey')]
    public function itRefusesTheEnvelopeBeforeAnyOperationOfTheKey(
        string $fixture,
        string $requestId,
        string $exception,
        string $message,
    ): void {
        // Given
        $response = $this->unverified($fixture);
        $key = $this->createMock(DecryptionKeyInterface::class);
        $key->expects($this->never())->method('unwrap');

        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $response->document);

        // When
        $this->validator()->validate($response, self::identityProvider()->withDecryptionKey($key), self::expected($requestId));
    }

    /**
     * @return iterable<string, array{string, string, class-string<MessageRefused>, string}>
     */
    public static function provideEnvelopesRefusedBeforeTheKey(): iterable
    {
        yield 'no Issuer of its own' => [
            'encrypted/response-encrypted-without-issuer-refused.xml',
            '_request',
            MalformedMessage::class,
            'The response holds a saml:EncryptedAssertion and has no saml:Issuer (M-8).',
        ];
        yield 'an answer to another request' => [
            'encrypted/response-encrypted-signed-assertion-accepted.xml',
            '_another-request',
            InResponseToMismatch::class,
            'The InResponseTo of the response is not the one the consumer expects (M-10).',
        ];
    }

    /**
     * §9.2 row 46, M-2, section 6.7, SAML Core §6.2
     */
    #[Test]
    #[DataProvider('provideAssertionsChangedAfterSigning')]
    public function itRefusesADecryptedAssertionWhoseOwnSignatureFails(string $fixture): void
    {
        // Given
        $response = $this->unverified($fixture);

        // Then
        $this->expectException(DigestMismatch::class);
        $this->expectExceptionMessageIs('The claimed element is not what was signed (D-8).');

        // When
        $this->validator()->validate($response, self::identityProvider()->withDecryptionKey(self::decryptionKey()), self::expected());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAssertionsChangedAfterSigning(): iterable
    {
        yield 'in an unsigned response' => ['encrypted/response-encrypted-assertion-changed-after-signing-refused.xml'];
        yield 'under a signed response' => [
            'encrypted/response-signed-over-encrypted-assertion-changed-after-signing-refused.xml',
        ];
    }

    /**
     * §9.2 row 44, section 6.7, section 6.1 step 2, section 5.5
     */
    #[Test]
    public function itRefusesAnEncryptedAssertionWithoutADecryptionKey(): void
    {
        // Given
        $response = $this->unverified('encrypted/response-signed-over-encrypted-assertion-accepted.xml');
        $message = 'The response holds a saml:EncryptedAssertion and the identity provider was given no key to decrypt it (section 6.7).';

        // Then
        $this->expectException(Unsupported::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $response->document);

        // When
        $this->validator()->validate($response, self::identityProvider(key: 'sp'), self::expected());
    }

    /**
     * §9.2 row 45, section 5.8, enc.md E-5
     */
    #[Test]
    public function itLetsTheRefusalOfEncThroughAsItIs(): void
    {
        // Given
        $response = $this->unverified('hostile/response-encrypted-assertion-refused.xml');

        // Then
        $this->expectException(MalformedEncryption::class);
        $this->expectExceptionMessageIs('An EncryptedData holds exactly one EncryptionMethod (E-5).');

        // When
        $this->validator()->validate($response, self::identityProvider()->withDecryptionKey(self::decryptionKey()), self::expected());
    }

    /**
     * M-11, section 6.7
     */
    #[Test]
    public function itRemembersAnAssertionThatArrivedEncrypted(): void
    {
        // Given
        $replay = new InMemoryReplayGuard();
        $this->validator($replay)->validate(
            $this->unverified('encrypted/response-encrypted-signed-assertion-accepted.xml'),
            self::identityProvider()->withDecryptionKey(self::decryptionKey()),
            self::expected(),
        );
        $response = $this->unverified('behaviour/response-signed-assertion-accepted.xml');

        // Then
        $this->expectException(Replayed::class);
        $this->expectExceptionMessageIs('The assertion was already accepted from its issuer (M-11).');

        // When
        $this->validator($replay)->validate($response, self::identityProvider()->withDecryptionKey(self::decryptionKey()), self::expected());
    }

    /**
     * §9.3 row 25, section 6.7, enc.md E-15, decision 0013
     */
    #[Test]
    #[DataProvider('provideCbcResponsesTheIdentityProviderSigned')]
    public function itReadsAnAssertionEncryptedInAesCbcUnderTheResponsesSignatureAsTheAssertionInClear(
        string $fixture,
    ): void {
        // Given
        $clear = $this->validator()->validate(
            $this->unverified('behaviour/response-signed-assertion-accepted.xml'),
            self::identityProvider(),
            self::expected(),
        );
        $response = $this->unverified($fixture);

        // When
        $accepted = $this->validator()->validate($response, self::identityProvider()->withDecryptionKey(self::decryptionKey()), self::expected());

        // Then
        static::assertEquals(
            [$clear->assertion, SignatureCoverage::AssertionAndResponse, '_response'],
            [$accepted->assertion, $accepted->coverage, $accepted->responseId],
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideCbcResponsesTheIdentityProviderSigned(): iterable
    {
        yield 'aes128-cbc' => ['encrypted/response-signed-over-encrypted-assertion-aes128-cbc-accepted.xml'];
        yield 'aes256-cbc under rsa-oaep-mgf1p and its DigestMethod of SHA-1' => [
            'encrypted/response-signed-over-encrypted-assertion-aes256-cbc-accepted.xml',
        ];
    }

    /**
     * §9.2 row 47, section 6.7, M-2, enc.md E-15
     */
    #[Test]
    #[DataProvider('provideCbcResponsesNoSignatureOfTheResponseCovers')]
    public function itRefusesAesCbcThatNoSignatureOfTheResponseCoversBeforeAnyKeyIsTouched(string $fixture): void
    {
        // Given
        $response = $this->unverified($fixture);
        $key = new RecordingDecryptionKey(self::decryptionKey());

        // When
        try {
            $this->validator()->validate($response, self::identityProvider()->withDecryptionKey($key), self::expected());
            static::fail('The validator opened AES-CBC that no signature of the response covers.');
        } catch (CoveringSignatureRequired $refusal) {
            // Then
            static::assertSame(
                [
                    'AES-CBC is decrypted only under a verified signature that covers the encrypted element (E-15).',
                    false,
                ],
                [$refusal->getMessage(), $key->asked],
            );
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideCbcResponsesNoSignatureOfTheResponseCovers(): iterable
    {
        yield 'no signature at all' => ['encrypted/response-encrypted-aes128-cbc-unsigned-assertion-refused.xml'];
        yield 'the assertion\'s signature only, inside the ciphertext' => [
            'encrypted/response-encrypted-aes256-cbc-signed-assertion-refused.xml',
        ];
        yield 'a signature of another element' => [
            'encrypted/response-encrypted-aes128-cbc-signature-in-extensions-refused.xml',
        ];
    }

    /**
     * §9.2 row 48, section 6.7, enc.md E-3, E-16
     *
     * @param 'idp'|'sp' $key
     */
    #[Test]
    #[DataProvider('provideCbcCiphertextsTheSignatureHoldsAndTheKeyDoesNotOpen')]
    public function itRefusesAnAlteredAesCbcCiphertextUnderAValidSignatureAsAWrongKey(string $fixture, string $key): void
    {
        // Given
        $response = $this->unverified($fixture);

        // Then
        $this->expectException(DecryptionFailed::class);
        $this->expectExceptionMessageIs('The data could not be decrypted (E-3).');

        // When
        $this->validator()->validate($response, self::identityProvider()->withDecryptionKey(self::decryptionKey($key)), self::expected());
    }

    /**
     * @return iterable<string, array{string, 'idp'|'sp'}>
     */
    public static function provideCbcCiphertextsTheSignatureHoldsAndTheKeyDoesNotOpen(): iterable
    {
        yield 'the count of the padding altered' => [
            'encrypted/response-signed-over-encrypted-assertion-aes128-cbc-padding-altered-refused.xml',
            'sp',
        ];
        yield 'the first block garbled' => [
            'encrypted/response-signed-over-encrypted-assertion-aes128-cbc-first-block-altered-refused.xml',
            'sp',
        ];
        yield 'a wrong key' => ['encrypted/response-signed-over-encrypted-assertion-aes128-cbc-accepted.xml', 'idp'];
    }

    /**
     * §9.2 row 49, section 5.5, section 6.7, enc.md E-15, section 5.4
     */
    #[Test]
    public function itOpensAResponseWithTheKeyGivenWithTheProviderThatSignedItOnly(): void
    {
        // Given
        $response = $this->unverified('encrypted/response-aes128-cbc-ciphertext-of-another-provider-signed-by-b-refused.xml');
        $keyOfA = new RecordingDecryptionKey(self::decryptionKey());
        $keyOfB = new RecordingDecryptionKey(self::decryptionKey('sp-b'));
        $providers = [
            'https://idp.example.com/saml' => self::identityProvider()->withDecryptionKey($keyOfA),
            'https://idp-b.example.com/saml' => self::identityProvider('https://idp-b.example.com/saml', 'idp-b')->withDecryptionKey($keyOfB),
        ];

        // When
        try {
            $this->validator()->validate($response, $providers[$response->issuer ?? ''], self::expected());
            static::fail('The validator read the ciphertext of a provider under the signature of another.');
        } catch (DecryptionFailed $failure) {
            // Then
            static::assertSame(
                [DecryptionFailed::MESSAGE, true, false],
                [$failure->getMessage(), $keyOfB->asked, $keyOfA->asked],
            );
        }
    }

    /**
     * §9.2 row 50, M-2, section 6.7
     */
    #[Test]
    public function itRefusesAnAesCbcCiphertextAlteredAfterTheSignatureBeforeAskingTheKey(): void
    {
        // Given
        $response = $this->unverified('encrypted/response-signed-over-encrypted-assertion-aes128-cbc-ciphertext-altered-after-signing-refused.xml');
        $key = new RecordingDecryptionKey(self::decryptionKey());

        // When
        try {
            $this->validator()->validate($response, self::identityProvider()->withDecryptionKey($key), self::expected());
            static::fail('The validator accepted a ciphertext altered after the signature.');
        } catch (DigestMismatch $refusal) {
            // Then
            static::assertSame(
                ['The claimed element is not what was signed (D-8).', false],
                [$refusal->getMessage(), $key->asked],
            );
        }
    }

    /**
     * §9.2 row 51, section 6.7, enc.md E-16
     */
    #[Test]
    #[DataProvider('provideCbcPlaintextsTheReadingRefuses')]
    public function itRefusesWhatTheReadingRefusesAfterAnAesCbcDecryptionAsTheOneFailure(string $fixture): void
    {
        // Given
        $response = $this->unverified($fixture);

        // Then
        $this->expectException(DecryptionFailed::class);
        $this->expectExceptionMessageIs('The data could not be decrypted (E-3).');

        // When
        $this->validator()->validate($response, self::identityProvider()->withDecryptionKey(self::decryptionKey()), self::expected());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideCbcPlaintextsTheReadingRefuses(): iterable
    {
        yield 'a samlp:Response, not an assertion (M-4)' => [
            'encrypted/response-signed-over-encrypted-aes128-cbc-not-an-assertion-refused.xml',
        ];
        yield 'the assertion\'s own signature failing, its NameID changed after signing (M-2)' => [
            'encrypted/response-signed-over-encrypted-aes128-cbc-assertion-changed-after-signing-refused.xml',
        ];
        yield 'the assertion\'s Issuer another entity (M-8)' => [
            'encrypted/response-signed-over-encrypted-aes128-cbc-assertion-of-another-issuer-refused.xml',
        ];
    }

    private static function expected(string $requestId = '_request'): ExpectedResponse
    {
        return ExpectedResponse::toRequest($requestId, 'https://sp.example.com/saml/acs', 'https://sp.example.com/saml');
    }

    /**
     * Section 5.5
     */
    private function validator(InMemoryReplayGuard $replay = new InMemoryReplayGuard()): ResponseValidator
    {
        return new ResponseValidator(
            SamlLoader::create(),
            new FrozenClock(new DateTimeImmutable('2026-09-30T12:00:00Z')),
            $replay,
            new TimeBounds(),
        );
    }
}
