<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit;

use Beffroi\Saml2\Bindings\Internal\Reception;
use Beffroi\Saml2\Bindings\Internal\Service;
use Beffroi\Saml2\Bindings\ReceivedResponse;
use Beffroi\Saml2\Bindings\Tests\Support\RedirectQuery;
use Beffroi\Saml2\Bindings\Tests\Support\TestKeys;
use Beffroi\Saml2\Model\Exception\InResponseToMismatch;
use Beffroi\Saml2\Model\Validation\SignatureCoverage;
use Beffroi\Xml\Dsig\Exception\SignatureMismatch;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 6.2 step 7, B-5, B-12, SAML Bindings §3.5.4, SAML Profiles §4.1.2
 */
final class ReceivedResponseTest extends TestCase
{
    use ReceptionFixtures;

    /**
     * B-5, section 6.2 step 7, M-2, SAML Profiles §4.1.4.5
     */
    #[Test]
    public function itValidatesTheResponseThroughTheModel(): void
    {
        // Given
        $received = self::postReceiver()->response(self::form('SAMLResponse', self::fixture(self::RESPONSE), 'state'));

        // When
        $accepted = $received->validate(self::responseValidator(), self::identityProvider(), self::expectedResponse());

        // Then
        static::assertSame(
            ['_response', '_assertion', SignatureCoverage::Assertion, 'state'],
            [$accepted->responseId, $accepted->assertion->id, $accepted->coverage, $received->relayState],
        );
    }

    /**
     * B-4, M-3, section 6.2 step 7
     */
    #[Test]
    public function itLetsTheRefusalOfTheSignatureThrough(): void
    {
        // Given
        $received = self::postReceiver()->response(self::form('SAMLResponse', self::fixture(self::RESPONSE)));
        $idp = self::identityProviderOf([TestKeys::certificate('sp')]);

        // Then
        $this->expectException(SignatureMismatch::class);
        $this->expectExceptionMessageIs('No trusted key verifies the signature over SignedInfo (D-7, D-8).');

        // When
        $received->validate(self::responseValidator(), $idp, self::expectedResponse());
    }

    /**
     * M-10, section 6.2 step 7
     */
    #[Test]
    public function itLetsTheRefusalOfTheModelThrough(): void
    {
        // Given
        $received = self::postReceiver()->response(self::form('SAMLResponse', self::fixture(self::RESPONSE)));

        // Then
        $this->expectException(InResponseToMismatch::class);
        $this->expectExceptionMessageIs('The InResponseTo of the response is not the one the consumer expects (M-10).');

        // When
        $received->validate(self::responseValidator(), self::identityProvider(), self::expectedResponse('_another'));
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
        $this->expectExceptionMessageIs('A ReceivedResponse is built from the reception of a Response (section 5.2).');

        // When
        new ReceivedResponse($reception);
    }

    /**
     * @return iterable<string, array{Reception}>
     */
    public static function provideReceptionsOfOtherMessages(): iterable
    {
        yield 'the reception of a LogoutResponse, over HTTP-POST' => [self::formReception(
            'SAMLResponse',
            self::fixture(self::LOGOUT_RESPONSE),
            Service::SingleLogout,
        )];
        yield 'the reception of an AuthnRequest in a query string' => [self::reception(
            RedirectQuery::carrying('SAMLRequest', self::fixture(self::AUTHN_REQUEST)),
            Service::SingleSignOn,
        )];
    }
}
