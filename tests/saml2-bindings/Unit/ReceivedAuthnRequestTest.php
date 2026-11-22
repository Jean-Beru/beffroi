<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit;

use function base64_encode;
use Beffroi\Saml2\Bindings\Exception\NoVerificationKey;
use Beffroi\Saml2\Bindings\Internal\Reception;
use Beffroi\Saml2\Bindings\Internal\Service;
use Beffroi\Saml2\Bindings\ReceivedAuthnRequest;
use Beffroi\Saml2\Bindings\Tests\Support\RedirectQuery;
use Beffroi\Saml2\Bindings\Tests\Support\TestKeys;
use Beffroi\Saml2\Model\Exception\SignatureRequired;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Validation\AcceptedAuthnRequest;
use Beffroi\Saml2\Model\Validation\Authentication;
use Beffroi\Xml\Dsig\Exception\AlgorithmUnavailable;
use Beffroi\Xml\Dsig\Exception\LimitExceeded;
use Beffroi\Xml\Dsig\Exception\SignatureMismatch;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function rawurldecode;
use function str_repeat;

/**
 * Section 6.1 step 12, B-2 to B-5, SAML Bindings §3.4.4.1
 */
final class ReceivedAuthnRequestTest extends TestCase
{
    use ReceptionFixtures;

    private const string MISMATCH = 'No trusted key verifies the detached signature (D-7, D-8).';

    /**
     * §9.3 row 7, B-5
     */
    #[Test]
    public function itAuthenticatesASignedRequestByTheBinding(): void
    {
        // Given
        $received = self::receiver()->authnRequest(self::query()->withRelayState('state')->signed()->toString());

        // When
        $accepted = $this->validate($received);

        // Then
        static::assertSame(
            [Authentication::Binding, '_4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b', 'state'],
            [$accepted->authentication, $accepted->request->id, $received->relayState],
        );
    }

    /**
     * §9.3 row 7, B-5, SAML Profiles §4.1.6
     */
    #[Test]
    public function itValidatesAnUnsignedRequestNobodyWantsSigned(): void
    {
        // Given
        $received = self::receiver()->authnRequest(self::query()->toString());

        // When
        $accepted = $this->validate($received);

        // Then
        static::assertSame(Authentication::None, $accepted->authentication);
    }

    /**
     * §9.2 row 20, B-5, M-2, SAML Metadata §2.4.4
     */
    #[Test]
    public function itRefusesAnUnsignedRequestTheServiceProviderSigns(): void
    {
        // Given
        $received = self::receiver()->authnRequest(self::query()->toString());

        // Then
        $this->expectException(SignatureRequired::class);
        $this->expectExceptionMessageIs('The message carries no ds:Signature, which the profile requires (M-2).');

        // When
        $this->validate($received, self::serviceProviderSigningItsRequests());
    }

    /**
     * §9.2 row 11, B-2, B-3, SAML Bindings §3.4.4.1
     */
    #[Test]
    public function itRefusesASigAlgChangedAfterSigning(): void
    {
        // Given
        $query = self::query()->withRelayState('state')->signed()->replaced('SigAlg', RedirectQuery::encode(SignatureAlgorithm::RsaSha512->value));
        $received = self::receiver()->authnRequest($query->toString());

        // Then
        $this->expectException(SignatureMismatch::class);
        $this->expectExceptionMessageIs(self::MISMATCH);

        // When
        $this->validate($received);
    }

    /**
     * §9.2 row 12, B-2, SAML Bindings §3.4.4.1
     */
    #[Test]
    #[DataProvider('provideQueriesSignedInAnotherOrder')]
    public function itRefusesOctetsSignedInAnotherOrder(RedirectQuery $query): void
    {
        // Given
        $received = self::receiver()->authnRequest($query->toString());

        // Then
        $this->expectException(SignatureMismatch::class);
        $this->expectExceptionMessageIs(self::MISMATCH);

        // When
        $this->validate($received);
    }

    /**
     * @return iterable<string, array{RedirectQuery}>
     */
    public static function provideQueriesSignedInAnotherOrder(): iterable
    {
        $query = self::query()->withRelayState('state')->withSigAlg(SignatureAlgorithm::RsaSha256)->inOrder(['RelayState', 'SAMLRequest', 'SigAlg']);
        $message = 'SAMLRequest=' . $query->value('SAMLRequest');
        $relayState = 'RelayState=' . $query->value('RelayState');
        $sigAlg = 'SigAlg=' . $query->value('SigAlg');

        yield 'in the order of arrival, RelayState, SAMLRequest, SigAlg' => [
            $query->signedOver($relayState . '&' . $message . '&' . $sigAlg),
        ];
        yield 'SigAlg first' => [$query->signedOver($sigAlg . '&' . $message . '&' . $relayState)];
    }

    /**
     * §9.2 row 13, B-2, SAML Bindings §3.4.4.1
     */
    #[Test]
    #[DataProvider('provideQueriesSignedOverOtherValues')]
    public function itRefusesOctetsSignedOverOtherValues(RedirectQuery $query): void
    {
        // Given
        $received = self::receiver()->authnRequest($query->toString());

        // Then
        $this->expectException(SignatureMismatch::class);
        $this->expectExceptionMessageIs(self::MISMATCH);

        // When
        $this->validate($received);
    }

    /**
     * @return iterable<string, array{RedirectQuery}>
     */
    public static function provideQueriesSignedOverOtherValues(): iterable
    {
        $query = self::query()->withRelayState('a state/1')->withSigAlg(SignatureAlgorithm::RsaSha256);

        yield 'the values decoded' => [$query->signedOver(
            'SAMLRequest=' . rawurldecode($query->value('SAMLRequest')) . '&RelayState=a state/1&SigAlg=' . SignatureAlgorithm::RsaSha256->value,
        )];
        yield 'the values encoded again in lowercase' => [$query->signedOver(
            RedirectQuery::inLowercase($query->octets()),
        )];
    }

    /**
     * §9.2 row 14, B-2, SAML Bindings §3.4.4.1
     */
    #[Test]
    public function itRefusesTheSignatureOfAnotherMessage(): void
    {
        // Given
        $other = RedirectQuery::carrying(
            'SAMLRequest',
            self::fixture('behaviour/authn-request-assertion-consumer-service-index.xml'),
        )
            ->withRelayState('state')
            ->signed();
        $query = self::query()->withRelayState('state')->withSigAlg(SignatureAlgorithm::RsaSha256)->with('Signature', $other->value('Signature'));
        $received = self::receiver()->authnRequest($query->toString());

        // Then
        $this->expectException(SignatureMismatch::class);
        $this->expectExceptionMessageIs(self::MISMATCH);

        // When
        $this->validate($received);
    }

    /**
     * §9.2 row 15, B-2, B-9, erratum E1
     */
    #[Test]
    #[DataProvider('provideRelayStatesChangedAfterSigning')]
    public function itRefusesARelayStateChangedAfterSigning(RedirectQuery $query): void
    {
        // Given
        $received = self::receiver()->authnRequest($query->toString());

        // Then
        $this->expectException(SignatureMismatch::class);
        $this->expectExceptionMessageIs(self::MISMATCH);

        // When
        $this->validate($received);
    }

    /**
     * @return iterable<string, array{RedirectQuery}>
     */
    public static function provideRelayStatesChangedAfterSigning(): iterable
    {
        $withRelayState = self::query()->withRelayState('state')->signed();

        yield 'changed' => [$withRelayState->replaced('RelayState', 'other')];
        yield 'added' => [self::query()->signed()->withRelayState('state')];
        yield 'removed' => [$withRelayState->without('RelayState')];
    }

    /**
     * §9.2 row 17, B-4, SAML Bindings §3.4.4.1
     */
    #[Test]
    public function itRefusesAKeyThePeerDoesNotList(): void
    {
        // Given
        $received = self::receiver()->authnRequest(self::query()->signed('idp')->toString());

        // Then
        $this->expectException(SignatureMismatch::class);
        $this->expectExceptionMessageIs(self::MISMATCH);

        // When
        $this->validate($received);
    }

    /**
     * §9.2 row 18, B-4, SAML Metadata §2.4.1.1
     */
    #[Test]
    public function itRefusesAPeerWithoutSigningCertificate(): void
    {
        // Given
        $received = self::receiver()->authnRequest(self::query()->signed()->toString());

        // Then
        $this->expectException(NoVerificationKey::class);
        $this->expectExceptionMessageIs('The metadata of the peer holds no signing certificate to verify the query string with (B-4).');

        // When
        $this->validate($received, self::serviceProviderOf([]));
    }

    /**
     * §9.2 row 19, D-14, SAML Bindings §3.4.4.1
     */
    #[Test]
    #[DataProvider('provideSignaturesOutsideTheBoundsOfDsig')]
    public function itRefusesASignatureOutsideTheBoundsOfDsig(int $bytes): void
    {
        // Given
        $query = self::query()
            ->withSigAlg(SignatureAlgorithm::RsaSha256)
            ->with('Signature', RedirectQuery::encode(base64_encode(str_repeat("\x01", $bytes))));
        $received = self::receiver()->authnRequest($query->toString());

        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('A signature is not between 256 and maxSignatureValueBytes, 1024 bytes (D-14).');

        // When
        $this->validate($received);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideSignaturesOutsideTheBoundsOfDsig(): iterable
    {
        yield '255 bytes' => [255];
        yield '1 025 bytes' => [1_025];
    }

    /**
     * §9.3 row 8, B-4, D-7, SAML Metadata §2.4.1.1
     */
    #[Test]
    public function itAcceptsTheSecondKeyOfARotation(): void
    {
        // Given
        $received = self::receiver()->authnRequest(self::query()->signed()->toString());

        // When
        $accepted = $this->validate($received, self::serviceProviderOf([
            TestKeys::certificate('idp'),
            TestKeys::certificate('sp'),
        ]));

        // Then
        static::assertSame(Authentication::Binding, $accepted->authentication);
    }

    /**
     * §9.3 row 13, B-3, dsig.md §5.1, SAML Bindings §3.4.4.1
     */
    #[Test]
    public function itAcceptsRsaPssWhereTheBuildHasIt(): void
    {
        // Given
        if (! SignatureAlgorithm::RsaPssSha256->isAvailable()) {
            static::markTestSkipped('This build cannot sign RSASSA-PSS: it needs PHP 8.5 and OpenSSL 3.1.');
        }
        $received = self::receiver()->authnRequest(self::query()->signed('sp', SignatureAlgorithm::RsaPssSha256)->toString());

        // When
        $accepted = $this->validate($received);

        // Then
        static::assertSame(Authentication::Binding, $accepted->authentication);
    }

    /**
     * §9.3 row 13, B-3, dsig.md §5.1, SAML Bindings §3.4.4.1
     */
    #[Test]
    public function itRefusesRsaPssWhereTheBuildLacksIt(): void
    {
        // Given
        if (SignatureAlgorithm::RsaPssSha256->isAvailable()) {
            static::markTestSkipped('This build verifies RSASSA-PSS: PHP 8.5 and OpenSSL 3.1.');
        }
        $query = self::query()
            ->withSigAlg(SignatureAlgorithm::RsaPssSha256)
            ->with('Signature', RedirectQuery::encode(base64_encode(str_repeat("\x01", 256))));
        $received = self::receiver()->authnRequest($query->toString());

        // Then
        $this->expectException(AlgorithmUnavailable::class);
        $this->expectExceptionMessageIs('This build cannot verify RSASSA-PSS: it needs PHP 8.5 and OpenSSL 3.1 (section 13).');

        // When
        $this->validate($received);
    }

    /**
     * Section 5.2, B-5
     */
    #[Test]
    #[DataProvider('provideReceptionsOfOtherMessages')]
    public function itRefusesTheReceptionOfAnotherMessage(Reception $reception): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A ReceivedAuthnRequest is built from the reception of an AuthnRequest (section 5.2).');

        // When
        new ReceivedAuthnRequest($reception);
    }

    /**
     * @return iterable<string, array{Reception}>
     */
    public static function provideReceptionsOfOtherMessages(): iterable
    {
        yield 'the reception of a LogoutRequest' => [self::reception(
            RedirectQuery::carrying('SAMLRequest', self::fixture(self::LOGOUT_REQUEST)),
            Service::SingleLogout,
        )];
        yield 'the reception of a LogoutResponse' => [self::reception(
            RedirectQuery::carrying('SAMLResponse', self::fixture(self::LOGOUT_RESPONSE)),
            Service::SingleLogout,
        )];
        yield 'the reception of a Response, over HTTP-POST' => [self::formReception(
            'SAMLResponse',
            self::fixture(self::RESPONSE),
            Service::AssertionConsumer,
        )];
    }

    private static function query(): RedirectQuery
    {
        return RedirectQuery::carrying('SAMLRequest', self::fixture(self::AUTHN_REQUEST));
    }

    private function validate(ReceivedAuthnRequest $received, ?ServiceProvider $sp = null): AcceptedAuthnRequest
    {
        return $received->validate(
            self::authnRequestValidator(),
            $sp ?? self::serviceProvider(),
            self::identityProvider(),
            self::SSO,
        );
    }
}
