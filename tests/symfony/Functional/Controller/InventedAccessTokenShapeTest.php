<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function base64_encode;
use App\Tests\Symfony\Functional\Token\InventedAccessTokenIssuer;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;
use function str_starts_with;

/**
 * Issue #239: a shape of access token the module knows nothing about, wired into this kernel as a
 * deployment would wire one, an issuer and a verifier answering to one name. The token endpoint mints in
 * it because a client registered for it, the UserInfo endpoint reads it back because a verifier answers
 * to the same name, and no class of `src` names it anywhere. The "invented-app" client of the test
 * configuration is the one registered for it.
 */
final class InventedAccessTokenShapeTest extends BrowserTestCase
{
    private const string CLIENT_ID = 'invented-app';

    private const string SECRET = 'invented-secret-of-at-least-32-characters';

    private const string REDIRECT_URI = 'https://invented.test/callback';

    /**
     * Architecture §4.6: the registration picks the issuer, and a name nothing in the module knows picks
     * the one the wiring added.
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
     * OIDC Core §5.3: a resource of the provider reads the token back through the verifier that
     * recognises it, which is what makes the shape a shape and not a value nobody can spend.
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

    /**
     * The whole code flow of the invented client, ending on the access token it was handed.
     */
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
