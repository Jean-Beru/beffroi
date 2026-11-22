<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit;

use Beffroi\Saml2\Bindings\BindingLimits;
use Beffroi\Saml2\Bindings\ReceivedLogoutRequest;
use Beffroi\Saml2\Bindings\ReceivedLogoutResponse;
use Beffroi\Saml2\Model\Validation\Authentication;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use function strlen;

/**
 * Section 9.1, B-5, B-9, B-12, section 8, M-2, SAML Bindings §3.4.4.1
 *
 * @phpstan-import-type Message from SendingFixtures
 */
final class RedirectRoundTripTest extends TestCase
{
    use SendingFixtures;

    /**
     * Section 9.1, B-2, B-5, §9.3 row 7
     */
    #[Test]
    #[DataProvider('provideAlgorithmsAndRelayStates')]
    public function itAcceptsASignedAuthnRequest(SignatureAlgorithm $algorithm, ?string $relayState): void
    {
        // Given
        $url = self::sender()->authnRequest(self::authnRequest(), self::signing('sp', $algorithm), $relayState);
        $received = self::receiver()->authnRequest(self::queryString($url));

        // When
        $accepted = $received->validate(
            self::authnRequestValidator(),
            self::serviceProvider(),
            self::identityProvider(),
            self::SSO,
        );

        // Then
        static::assertSame(
            [Authentication::Binding, self::authnRequest()->id, $relayState],
            [$accepted->authentication, $accepted->request->id, $received->relayState],
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
        $url = self::sender()->authnRequest(self::authnRequest(), null, $relayState);
        $received = self::receiver()->authnRequest(self::queryString($url));

        // When
        $accepted = $received->validate(
            self::authnRequestValidator(),
            self::serviceProvider(),
            self::identityProvider(),
            self::SSO,
        );

        // Then
        static::assertSame(
            [Authentication::None, self::authnRequest()->id, $relayState],
            [$accepted->authentication, $accepted->request->id, $received->relayState],
        );
    }

    /**
     * Section 9.1, B-2, B-5, B-12, SAML Profiles §4.4.4.1
     */
    #[Test]
    #[DataProvider('provideAlgorithmsAndRelayStates')]
    public function itAcceptsASignedLogoutRequest(SignatureAlgorithm $algorithm, ?string $relayState): void
    {
        // Given
        $url = self::sender()->logoutRequest(self::logoutRequest(), self::signing('idp', $algorithm), $relayState);
        $received = self::receiver()->logoutMessage(self::queryString($url));
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
            [Authentication::Binding, self::LOGOUT_REQUEST_ID, $relayState],
            [$accepted->authentication, $accepted->request->id, $received->relayState],
        );
    }

    /**
     * Section 9.1, B-2, B-5, B-12, SAML Profiles §4.4.4.1
     */
    #[Test]
    #[DataProvider('provideAlgorithmsAndRelayStates')]
    public function itAcceptsASignedLogoutResponse(SignatureAlgorithm $algorithm, ?string $relayState): void
    {
        // Given
        $url = self::sender()->logoutResponse(self::logoutResponse(), self::signing('sp', $algorithm), $relayState);
        $received = self::receiver()->logoutMessage(self::queryString($url));
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
            [Authentication::Binding, self::logoutResponse()->id, $relayState],
            [$accepted->authentication, $accepted->response->id, $received->relayState],
        );
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
        yield 'with a RelayState of 1 024 bytes, every byte escaped' => [self::longestRelayState()];
    }

    /**
     * §9.3 row 5, section 7, B-7, B-9
     *
     * @param Message $message
     */
    #[Test]
    #[DataProvider('provideSignedMessages')]
    public function itCarriesTheLongestRelayStateUnderTheDefaultBound(string $message): void
    {
        // Given
        $url = self::send($message, self::longestRelayState());

        // When
        $received = match ($message) {
            'an AuthnRequest' => self::receiver()->authnRequest(self::queryString($url)),
            default => self::receiver()->logoutMessage(self::queryString($url)),
        };

        // Then
        static::assertSame(
            [3_072, true, self::longestRelayState()],
            [
                strlen(self::query($url)->value('RelayState')),
                strlen(self::queryString($url)) <= new BindingLimits()->maxQueryStringBytes,
                $received->relayState,
            ],
        );
    }

    /**
     * @return iterable<string, array{Message}>
     */
    public static function provideSignedMessages(): iterable
    {
        yield 'an AuthnRequest' => ['an AuthnRequest'];
        yield 'a LogoutRequest' => ['a LogoutRequest'];
        yield 'a LogoutResponse' => ['a LogoutResponse'];
    }

    /**
     * §9.3 row 3, section 6.1 step 2, section 6.3 step 6, M-8
     */
    #[Test]
    public function itAcceptsAnAuthnRequestWhoseDestinationHoldsItsOwnQuery(): void
    {
        // Given
        $destination = self::SSO . '?tenant=acme';
        $url = self::sender()->authnRequest(self::authnRequest($destination), self::signing('sp'), 'state');
        $received = self::receiver()->authnRequest(self::queryString($url));

        // When
        $accepted = $received->validate(
            self::authnRequestValidator(),
            self::serviceProvider(),
            self::identityProviderAt($destination),
            $destination,
        );

        // Then
        static::assertSame(
            [Authentication::Binding, $destination, 'state'],
            [$accepted->authentication, $accepted->request->destination, $received->relayState],
        );
    }
}
