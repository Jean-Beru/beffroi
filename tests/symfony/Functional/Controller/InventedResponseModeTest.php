<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use App\Tests\Symfony\Functional\ResponseMode\InventedResponseModeRenderer;
use PHPUnit\Framework\Attributes\Test;
use function parse_str;
use Symfony\Component\HttpFoundation\Response;

final class InventedResponseModeTest extends BrowserTestCase
{
    /**
     * Multiple Response Type Encoding Practices §2.1
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
     * OIDC Discovery §3
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
     * OIDC Core §3.1.2.6
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
