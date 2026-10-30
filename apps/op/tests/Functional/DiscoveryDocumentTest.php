<?php

declare(strict_types=1);

namespace App\Tests\Functional;

use function json_decode;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * What the discovery document of this application announces to a deployment that names nothing the
 * repository does not (issues #843 and #922). The suite reads .env and .env.test and never .env.local, so what
 * it boots on is what "composer dump-env prod" compiles into an image, plus the fixtures of .env.test; and its
 * kernel wires what production wires, plus the demonstration and the client of config/packages/test/, neither of
 * which announces anything of its own.
 */
final class DiscoveryDocumentTest extends BrowserTestCase
{
    /**
     * RFC 8705 §5: an alias sends a client that presents a certificate to another host. A deployment that
     * serves none announces none, and the host of the development stack answers on a desk and nowhere else:
     * "castor provision" writes it into .env.local, and no image announces it.
     */
    #[Test]
    public function itAnnouncesNoMutualTlsAliasForAHostTheDeploymentDidNotName(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        $document = json_decode(self::string($response->getContent()), true);
        static::assertIsArray($document);
        static::assertArrayNotHasKey('mtls_endpoint_aliases', $document);
    }

    /**
     * RFC 7591, decision 0009 (issue #911): a deployment that names no registration mode has no registration
     * endpoint, and the image declares no client either, so a client reaches it once its deployment names a
     * mode. The open mode of the development stack is written by "castor provision" into .env.local, and no
     * image announces it.
     */
    #[Test]
    public function itAnnouncesNoRegistrationEndpointForAModeTheDeploymentDidNotName(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        $document = json_decode(self::string($response->getContent()), true);
        static::assertIsArray($document);
        static::assertArrayNotHasKey('registration_endpoint', $document);
    }

    /**
     * RFC 9396 §10 (issue #922): "authorization_details_types_supported" is how a provider advertises that it serves
     * rich authorization requests, and with which types. A type is a class of a deployment, and the one of the API of
     * the demonstration is the lab's, wired in development alone: a deployment that wires none advertises none.
     */
    #[Test]
    public function itAnnouncesNoTypeOfAuthorizationDetailTheDeploymentDidNotWire(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        $document = json_decode(self::string($response->getContent()), true);
        static::assertIsArray($document);
        static::assertArrayNotHasKey('authorization_details_types_supported', $document);
    }
}
