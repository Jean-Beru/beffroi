<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Validation;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\Replayed;
use Beffroi\Saml2\Model\Exception\SignatureRequired;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Support\FrozenClock;
use Beffroi\Saml2\Model\Tests\Support\InMemoryReplayGuard;
use Beffroi\Saml2\Model\Tests\Unit\Internal\Response\ResponseFixtures;
use Beffroi\Saml2\Model\Validation\ExpectedResponse;
use Beffroi\Saml2\Model\Validation\ResponseValidator;
use Beffroi\Saml2\Model\Validation\SignatureCoverage;
use Beffroi\Saml2\Model\Validation\TimeBounds;
use Beffroi\Xml\Dsig\Exception\DigestMismatch;
use Beffroi\Xml\Enc\DecryptionKeyInterface;
use Beffroi\Xml\Enc\Exception\DecryptionFailed;
use Beffroi\Xml\Enc\Exception\MalformedEncryption;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 6.7, section 6.1 steps 2 to 6, M-1, M-2, M-4, M-8, M-11: a response whose assertion is encrypted, read by a
 * validator built with the key of the service provider, the response's signature verified before any decryption, every
 * failure of the decryption Enc's own (SAML Core §2.3.4, §6.2; enc.md E-3). The responses are those xmlsec1 encrypted,
 * under tests/saml2-model/Fixture/encrypted/.
 */
final class ResponseValidatorDecryptionTest extends TestCase
{
    use ResponseFixtures;

    /**
     * §9.3 row 23, section 6.7, M-1: the signed assertion xmlsec1 encrypted in AES-GCM for the test key of the service
     * provider is read as the same assertion in clear, its own signature verified once it is decrypted.
     */
    #[Test]
    public function itReadsAnEncryptedAssertionAsTheSameAssertionInClear(): void
    {
        // Given
        $clear = $this->validator(null)->validate(
            $this->unverified('behaviour/response-signed-assertion-accepted.xml'),
            self::identityProvider(),
            self::expected(),
        );
        $response = $this->unverified('encrypted/response-encrypted-signed-assertion-accepted.xml');

        // When
        $accepted = $this->validator(self::decryptionKey())->validate($response, self::identityProvider(), self::expected());

        // Then
        static::assertEquals($clear, $accepted);
    }

    /**
     * §9.3 row 24, M-1, M-2, section 6.7: an assertion encrypted without a signature, under a response xmlsec1 signed
     * over its ciphertext, is read from the document of its decryption, the response's signature covering it.
     */
    #[Test]
    public function itReadsAnUnsignedAssertionWhoseCiphertextTheResponsesSignatureCovered(): void
    {
        // Given
        $response = $this->unverified('encrypted/response-signed-over-encrypted-assertion-accepted.xml');

        // When
        $accepted = $this->validator(self::decryptionKey())->validate($response, self::identityProvider(), self::expected());

        // Then
        static::assertSame(
            [SignatureCoverage::Response, '_response', '_assertion', '_7a2f4c1d9e'],
            [$accepted->coverage, $accepted->responseId, $accepted->assertion->id, $accepted->assertion->nameId->value],
        );
    }

    /**
     * §9.2 row 38, section 6.7, enc.md E-3: a ciphertext altered by one byte, a key that is not the one it was
     * encrypted for, and a tag truncated by one byte are refused with the one failure of Enc, whatever failed.
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
        $this->validator(self::decryptionKey($key))->validate($response, self::identityProvider(), self::expected());
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
     * §9.2 row 39, M-2, section 6.7, SAML Core §6.2: under a signed response, an altered ciphertext is refused by the
     * signature of the response, which is verified before any decryption: decrypted first, it would have failed as
     * DecryptionFailed.
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
        $this->validator(self::decryptionKey())->validate($response, self::identityProvider(), self::expected());
    }

    /**
     * §9.2 row 40, M-2, section 6.7: an assertion encrypted without a signature, in an unsigned response, is covered by
     * nothing: anyone encrypts for the key of the service provider.
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
        $this->validator(self::decryptionKey())->validate($response, self::identityProvider(), self::expected());
    }

    /**
     * §9.2 row 41, M-4, section 6.7: a plaintext that is not a saml:Assertion, a samlp:Response here, is refused,
     * whatever it holds.
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
        $this->validator(self::decryptionKey())->validate($response, self::identityProvider(), self::expected());
    }

    /**
     * §9.2 row 42, M-8, SAML Profiles §4.1.4.2 as corrected by E17: a response whose assertion is encrypted carries its
     * own Issuer, signed or not.
     */
    #[Test]
    public function itRequiresTheIssuerOfAResponseWhoseAssertionIsEncrypted(): void
    {
        // Given
        $response = $this->unverified('encrypted/response-encrypted-without-issuer-refused.xml');
        $message = 'The response holds a saml:EncryptedAssertion and has no saml:Issuer (M-8).';

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $response->document);

        // When
        $this->validator(self::decryptionKey())->validate($response, self::identityProvider(), self::expected());
    }

    /**
     * §9.2 row 44, section 6.7, section 6.1 step 2: a validator built without a decryption key refuses an encrypted
     * assertion by name before any key is touched: under metadata that would refuse the signature of the response, the
     * refusal is still that one.
     */
    #[Test]
    public function itRefusesAnEncryptedAssertionWithoutADecryptionKey(): void
    {
        // Given
        $response = $this->unverified('encrypted/response-signed-over-encrypted-assertion-accepted.xml');
        $message = 'The response holds a saml:EncryptedAssertion and the validator holds no key to decrypt it (section 6.7).';

        // Then
        $this->expectException(Unsupported::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $response->document);

        // When
        $this->validator(null)->validate($response, self::identityProvider(key: 'sp'), self::expected());
    }

    /**
     * §9.2 row 45, section 5.8, enc.md E-5: what the reading model of Enc refuses, an xenc:EncryptedData that holds
     * nothing, passes as Enc refuses it.
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
        $this->validator(self::decryptionKey())->validate($response, self::identityProvider(), self::expected());
    }

    /**
     * M-11, section 6.7: an assertion accepted encrypted is remembered under its issuer and its ID, so that the same
     * assertion in clear is a replay.
     */
    #[Test]
    public function itRemembersAnAssertionThatArrivedEncrypted(): void
    {
        // Given
        $replay = new InMemoryReplayGuard();
        $this->validator(self::decryptionKey(), $replay)->validate(
            $this->unverified('encrypted/response-encrypted-signed-assertion-accepted.xml'),
            self::identityProvider(),
            self::expected(),
        );
        $response = $this->unverified('behaviour/response-signed-assertion-accepted.xml');

        // Then
        $this->expectException(Replayed::class);
        $this->expectExceptionMessageIs('The assertion was already accepted from its issuer (M-11).');

        // When
        $this->validator(self::decryptionKey(), $replay)->validate($response, self::identityProvider(), self::expected());
    }

    /**
     * A response to the request _request, received at our assertion consumer service, for our entity ID.
     */
    private static function expected(): ExpectedResponse
    {
        return ExpectedResponse::toRequest('_request', 'https://sp.example.com/saml/acs', 'https://sp.example.com/saml');
    }

    /**
     * The validator of the service provider, built with $key, its clock frozen at 2026-09-30T12:00:00Z, a second after
     * the responses were issued.
     */
    private function validator(
        ?DecryptionKeyInterface $key,
        InMemoryReplayGuard $replay = new InMemoryReplayGuard(),
    ): ResponseValidator {
        return new ResponseValidator(
            SamlLoader::create(),
            new FrozenClock(new DateTimeImmutable('2026-09-30T12:00:00Z')),
            $replay,
            new TimeBounds(),
            $key,
        );
    }
}
