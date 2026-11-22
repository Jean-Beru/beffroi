<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit;

use Beffroi\Saml2\Bindings\ReceivedLogoutRequest;
use Beffroi\Saml2\Bindings\ReceivedLogoutResponse;
use Beffroi\Saml2\Bindings\Tests\Support\BrowserForm;
use Beffroi\Saml2\Model\Exception\UnsuccessfulResponse;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\Validation\Authentication;
use Beffroi\Saml2\Model\Validation\SignatureCoverage;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * Section 9.1, B-5, B-9, B-12, M-2, SAML Bindings §3.5.4
 */
final class PostRoundTripTest extends TestCase
{
    use SendingFixtures;

    /**
     * Section 9.1, B-5, M-2
     */
    #[Test]
    #[DataProvider('provideAlgorithmsAndRelayStates')]
    public function itAcceptsASignedAuthnRequest(SignatureAlgorithm $algorithm, ?string $relayState): void
    {
        // Given
        $form = self::postSender()->authnRequest(self::authnRequest(), self::signing('sp', $algorithm), $relayState);
        $received = self::postReceiver()->authnRequest(BrowserForm::submitted($form));

        // When
        $accepted = $received->validate(
            self::authnRequestValidator(),
            self::serviceProvider(),
            self::identityProvider(),
            self::SSO,
        );

        // Then
        static::assertSame(
            [Authentication::XmlSignature, self::AUTHN_REQUEST_ID, $relayState, Binding::HttpPost],
            [$accepted->authentication, $accepted->request->id, $received->relayState, $received->binding],
        );
    }

    /**
     * Section 9.1, B-5, §9.3 row 7
     */
    #[Test]
    #[DataProvider('provideRelayStates')]
    public function itAcceptsAnUnsignedAuthnRequest(?string $relayState): void
    {
        // Given
        $form = self::postSender()->authnRequest(self::authnRequest(), null, $relayState);
        $received = self::postReceiver()->authnRequest(BrowserForm::submitted($form));

        // When
        $accepted = $received->validate(
            self::authnRequestValidator(),
            self::serviceProvider(),
            self::identityProvider(),
            self::SSO,
        );

        // Then
        static::assertSame(
            [Authentication::None, self::AUTHN_REQUEST_ID, $relayState],
            [$accepted->authentication, $accepted->request->id, $received->relayState],
        );
    }

    /**
     * Section 9.1, B-5, B-12, SAML Profiles §4.4.4.1
     */
    #[Test]
    #[DataProvider('provideAlgorithmsAndRelayStates')]
    public function itAcceptsASignedLogoutRequest(SignatureAlgorithm $algorithm, ?string $relayState): void
    {
        // Given
        $form = self::postSender()->logoutRequest(self::logoutRequest(), self::signing('idp', $algorithm), $relayState);
        $received = self::postReceiver()->logoutMessage(BrowserForm::submitted($form));
        static::assertInstanceOf(ReceivedLogoutRequest::class, $received);

        // When
        $accepted = $received->validate(
            self::logoutRequestValidator(),
            self::identityProvider(),
            self::serviceProvider(),
            self::SP_SLO,
        );

        // Then
        static::assertSame(
            [Authentication::XmlSignature, self::LOGOUT_REQUEST_ID, $relayState],
            [$accepted->authentication, $accepted->request->id, $received->relayState],
        );
    }

    /**
     * Section 9.1, B-5, B-12, SAML Profiles §4.4.4.1
     */
    #[Test]
    #[DataProvider('provideAlgorithmsAndRelayStates')]
    public function itAcceptsASignedLogoutResponse(SignatureAlgorithm $algorithm, ?string $relayState): void
    {
        // Given
        $form = self::postSender()->logoutResponse(self::logoutResponse(), self::signing('sp', $algorithm), $relayState);
        $received = self::postReceiver()->logoutMessage(BrowserForm::submitted($form));
        static::assertInstanceOf(ReceivedLogoutResponse::class, $received);

        // When
        $accepted = $received->validate(
            self::logoutResponseValidator(),
            self::serviceProvider(),
            self::identityProvider(),
            self::IDP_SLO,
            self::LOGOUT_REQUEST_ID,
        );

        // Then
        static::assertSame(
            [Authentication::XmlSignature, self::logoutResponse()->id, $relayState],
            [$accepted->authentication, $accepted->response->id, $received->relayState],
        );
    }

    /**
     * Section 9.1, B-5, M-2, SAML Profiles §4.1.4.5
     *
     * @param 'a Response'|'a Response signed whole' $message
     */
    #[Test]
    #[DataProvider('provideResponses')]
    public function itAcceptsAResponse(
        string $message,
        SignatureAlgorithm $algorithm,
        ?string $relayState,
        SignatureCoverage $coverage,
    ): void {
        // Given
        $received = self::postReceiver()->response(BrowserForm::submitted(self::post($message, $relayState, $algorithm)));

        // When
        $accepted = $received->validate(
            self::responseValidator('2026-10-01T12:00:00Z'),
            self::identityProvider(),
            self::expectedResponse(self::AUTHN_REQUEST_ID),
        );

        // Then
        static::assertEquals(
            [self::RESPONSE_ID, self::assertion(), $coverage, $relayState],
            [$accepted->responseId, $accepted->assertion, $accepted->coverage, $received->relayState],
        );
    }

    /**
     * @return iterable<string, array{'a Response'|'a Response signed whole', SignatureAlgorithm, ?string, SignatureCoverage}>
     */
    public static function provideResponses(): iterable
    {
        foreach (self::provideAlgorithmsAndRelayStates() as $name => [$algorithm, $relayState]) {
            yield 'the assertion signed, ' . $name => [
                'a Response',
                $algorithm,
                $relayState,
                SignatureCoverage::Assertion,
            ];
            yield 'the response signed too, ' . $name => [
                'a Response signed whole',
                $algorithm,
                $relayState,
                SignatureCoverage::AssertionAndResponse,
            ];
        }
    }

    /**
     * Section 9.1, M-13, SAML Profiles §4.1.4.2
     *
     * @param 'an unsigned failure'|'a failure' $message
     */
    #[Test]
    #[DataProvider('provideFailures')]
    public function itReadsAFailure(string $message, ?string $relayState): void
    {
        // Given
        $received = self::postReceiver()->response(BrowserForm::submitted(self::post($message, $relayState)));

        // When
        try {
            $received->validate(
                self::responseValidator('2026-10-01T12:00:00Z'),
                self::identityProvider(),
                self::expectedResponse(self::AUTHN_REQUEST_ID),
            );
            static::fail('The failure is not reported.');
        } catch (UnsuccessfulResponse $failure) {
            // Then
            static::assertSame(
                [StatusCode::Responder, SecondLevelStatusCode::AuthnFailed, $relayState],
                [$failure->status->code, $failure->status->secondLevel, $received->relayState],
            );
        }
    }

    /**
     * @return iterable<string, array{'an unsigned failure'|'a failure', ?string}>
     */
    public static function provideFailures(): iterable
    {
        foreach (self::provideRelayStates() as $name => [$relayState]) {
            yield 'unsigned, ' . $name => ['an unsigned failure', $relayState];
            yield 'signed, ' . $name => ['a failure', $relayState];
        }
    }

    /**
     * @return iterable<string, array{SignatureAlgorithm, ?string}>
     */
    public static function provideAlgorithmsAndRelayStates(): iterable
    {
        foreach (self::algorithms() as $algorithm) {
            foreach (self::provideRelayStates() as $name => [$relayState]) {
                yield sprintf('%s, %s', $algorithm->name, $name) => [$algorithm, $relayState];
            }
        }
    }

    /**
     * @return iterable<string, array{?string}>
     */
    public static function provideRelayStates(): iterable
    {
        yield 'without RelayState' => [null];
        yield 'with a RelayState of 80 bytes' => [self::RELAY_STATE];
        yield 'with a RelayState of 1 024 bytes' => [self::longestRelayState()];
    }
}
