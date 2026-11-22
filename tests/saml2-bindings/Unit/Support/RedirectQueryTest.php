<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit\Support;

use function base64_decode;
use Beffroi\Saml2\Bindings\Tests\Support\RedirectQuery;
use Beffroi\Saml2\Bindings\Tests\Support\TestKeys;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use Beffroi\Xml\Dsig\VerificationKey;
use Beffroi\Xml\Dsig\VerificationKeys;
use Beffroi\Xml\Dsig\Verifier;
use function gzinflate;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function rawurldecode;

/**
 * Sections 9.2 and 9.3, SAML Bindings §3.4.4.1
 */
final class RedirectQueryTest extends TestCase
{
    private const string XML = '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>';

    /**
     * SAML Bindings §3.4.4.1 step 2 and 3
     */
    #[Test]
    public function itCarriesTheMessageRawDeflated(): void
    {
        // Given
        $query = RedirectQuery::carrying('SAMLRequest', self::XML);

        // When
        $inflated = gzinflate((string) base64_decode(rawurldecode($query->value('SAMLRequest')), true));

        // Then
        static::assertSame(self::XML, $inflated);
    }

    /**
     * B-2, SAML Bindings §3.4.4.1
     */
    #[Test]
    public function itTakesTheOctetsInTheOrderOfTheBinding(): void
    {
        // Given
        $query = RedirectQuery::carrying('SAMLRequest', self::XML)
            ->withRelayState('a b')
            ->withSigAlg(SignatureAlgorithm::RsaSha256)
            ->inOrder(['SigAlg', 'RelayState', 'SAMLRequest']);

        // When
        $octets = $query->octets();

        // Then
        static::assertSame(
            'SAMLRequest=' . $query->value('SAMLRequest') . '&RelayState=a%20b&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256',
            $octets,
        );
    }

    /**
     * D-8
     */
    #[Test]
    public function itSignsTheOctetsWithTheTestKey(): void
    {
        // Given
        $query = RedirectQuery::carrying('SAMLRequest', self::XML)->withRelayState('state')->signed('idp');
        $key = VerificationKey::fromCertificateBase64(TestKeys::certificate('idp'));

        // When
        $verified = new Verifier(SamlLoader::create())->verifyDetached(
            $query->octets(),
            (string) base64_decode(rawurldecode($query->value('Signature')), true),
            SignatureAlgorithm::RsaSha256,
            new VerificationKeys([$key]),
        );

        // Then
        static::assertSame($key, $verified);
    }

    /**
     * B-8
     */
    #[Test]
    public function itEscapesInLowercase(): void
    {
        // When / Then
        static::assertSame('AB%2fc%3d', RedirectQuery::encodeInLowercase('AB/c='));
    }

    /**
     * Section 6.1 step 2
     */
    #[Test]
    public function itReadsAQueryStringBack(): void
    {
        // Given
        $queryString = 'tenant=acme&SAMLRequest=a%2Bb%3D%3D&flag&RelayState=x=y';

        // When
        $query = RedirectQuery::of($queryString);

        // Then
        static::assertSame(
            [['tenant', 'SAMLRequest', 'flag', 'RelayState'], 'a%2Bb%3D%3D', '', 'x=y'],
            [$query->names(), $query->value('SAMLRequest'), $query->value('flag'), $query->value('RelayState')],
        );
    }
}
