<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function base64_encode;
use App\Tests\Symfony\Functional\Token\InventedAccessTokenIssuer;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;
use function str_starts_with;

final class InventedAccessTokenShapeTest extends BrowserTestCase
{
    private const string CLIENT_ID = 'invented-app';

    private const string SECRET = 'invented-secret-of-at-least-32-characters';

    private const string REDIRECT_URI = 'https://invented.test/callback';

    /**
     * Architecture §4.6
     */
    #[Test]
    public function theTokenEndpointMintsInTheShapeTheClientRegisteredFor(): void
    {
        // When
        $accessToken = $this->accessToken();

        // Then
        static::assertTrue(str_starts_with($accessToken, InventedAccessTokenIssuer::PREFIX), $accessToken);
    }

    /**
     * OIDC Core §5.3
     */
    #[Test]
    public function theUserInfoEndpointReadsATokenOfThatShapeBack(): void
    {
        // Given
        $accessToken = $this->accessToken();

        // When
        $this->browser->request('GET', '/userinfo', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $accessToken,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('alice-subject', self::json($response)['sub']);
    }

    private function accessToken(): string
    {
        self::signingKey();
        $this->signIn(self::user('alice'));
        $this->browser->request('GET', '/authorize', self::authorizationParameters(self::CLIENT_ID, [
            'redirect_uri' => self::REDIRECT_URI,
        ]));
        $code = self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => self::REDIRECT_URI,
                'code_verifier' => self::CODE_VERIFIER,
            ],
            server: [
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode(self::CLIENT_ID . ':' . self::SECRET),
            ],
        );
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return self::string(self::json($response)['access_token']);
    }
}
