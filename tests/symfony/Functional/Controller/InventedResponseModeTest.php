<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Controller;

use Heidi\Bundle\Tests\Functional\ResponseMode\InventedResponseModeRenderer;
use PHPUnit\Framework\Attributes\Test;
use function parse_str;
use Symfony\Component\HttpFoundation\Response;

/**
 * Issue #240: a way of answering the authorization endpoint the module knows nothing about, wired into this
 * kernel as a deployment would wire one. A request may ask for it, the document announces it, and the
 * endpoint answers in it, without a class of `src` naming it anywhere: there is no enumeration of response
 * modes to add a case to.
 */
final class InventedResponseModeTest extends BrowserTestCase
{
    /**
     * Multiple Response Type Encoding Practices §2.1: what a request may ask for is what the integration
     * wired, read from the ways of answering themselves.
     */
    #[Test]
    public function theEndpointAnswersInTheModeTheWiringAdded(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters('oidc-demo', [
            'response_mode' => InventedResponseModeRenderer::MODE,
        ]));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertSame(InventedResponseModeRenderer::CONTENT_TYPE, $response->headers->get('Content-Type'));
        parse_str(self::string($response->getContent()), $parameters);
        static::assertArrayHasKey('code', $parameters);
        static::assertSame('https://op.test', $parameters['iss']);
    }

    /**
     * OIDC Discovery §3: the document announces the modes the integration wired and no other, so a mode it
     * announces is a mode the endpoint can deliver.
     */
    #[Test]
    public function theDocumentAnnouncesTheModeTheWiringAdded(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        $announced = self::json($this->browser->getResponse())['response_modes_supported'];
        static::assertIsArray($announced);
        static::assertContains(InventedResponseModeRenderer::MODE, $announced, self::string(json_encode($announced)));
    }

    /**
     * OIDC Core §3.1.2.6: the refusal of the second stage travels in the mode of the request, whichever mode
     * that is, so a client that asked for a wired mode hears everything back in it.
     */
    #[Test]
    public function aRefusalTravelsInThatModeToo(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters('oidc-demo', [
            'response_mode' => InventedResponseModeRenderer::MODE,
            'response_type' => 'token',
        ]));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertSame(InventedResponseModeRenderer::CONTENT_TYPE, $response->headers->get('Content-Type'));
        parse_str(self::string($response->getContent()), $parameters);
        static::assertSame('unsupported_response_type', $parameters['error']);
    }
}
