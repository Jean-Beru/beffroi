<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\Response;

use Beffroi\Saml2\Model\Exception\SignatureRequired;
use Beffroi\Saml2\Model\Internal\Response\SignedResponse;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\SamlLoader;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 6.1 step 3, M-1, M-2, M-3
 */
final class SignedResponseTest extends TestCase
{
    use ResponseFixtures;

    /**
     * Section 6.1 step 3
     */
    #[Test]
    public function itReadsAnUnsignedResponseAsItArrived(): void
    {
        // Given
        $received = $this->document('behaviour/response-signed-assertion-accepted.xml')->root();

        // When
        $response = SignedResponse::of($received, self::identityProvider(), SamlLoader::create());

        // Then
        static::assertSame([$received, null], [$response->root, $response->verification]);
    }

    /**
     * M-1, D-10
     */
    #[Test]
    public function itReadsASignedResponseFromItsVerification(): void
    {
        // Given
        $document = $this->document('behaviour/response-signed-response-accepted.xml');
        $received = $document->root();

        // When
        $response = SignedResponse::of($received, self::identityProvider(), SamlLoader::create());

        // Then
        static::assertSame($response->verification?->document->root(), $response->root);
        static::assertNotSame($received, $response->root);
    }

    /**
     * M-3, section 5.3
     */
    #[Test]
    public function itRefusesASignatureNoKeyOfTheMetadataCanVerify(): void
    {
        // Given
        $document = $this->document('behaviour/response-signed-response-accepted.xml');
        $idp = new IdentityProvider(
            'https://idp.example.com/saml',
            [],
            [],
            [new Endpoint(Binding::HttpRedirect, 'https://idp.example.com/saml/sso')],
        );

        // Then
        $this->expectException(SignatureRequired::class);
        $this->expectExceptionMessageIs('The metadata of the peer holds no signing key to verify the message with (M-3).');

        // When
        SignedResponse::of($document->root(), $idp, SamlLoader::create());
    }
}
