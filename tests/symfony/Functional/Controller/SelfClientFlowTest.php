<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function base64_encode;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

final class SelfClientFlowTest extends BrowserTestCase
{
    private const string CALLBACK = 'https://op.test/application/oidc/callback';

    private const string PAGE = 'https://op.test/application/me';

    private const string SECRET = 'the-secret-of-the-host-application-of-this-kernel';

    /**
     * OIDC Core §3.1.2.4
     */
    #[Test]
    public function theApplicationIsAnsweredWithACodeNobodyIsAskedToConsentTo(): void
    {
        // Given
        $this->signIn(self::user());

        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters('app', [
            'redirect_uri' => self::CALLBACK,
        ]));

        // Then
        static::assertStringStartsWith(self::CALLBACK . '?', self::string($this->browser->getResponse()->headers->get('Location')));
        static::assertArrayHasKey('code', self::redirectedQuery($this->browser->getResponse()));
    }

    /**
     * RFC 6749 §2.3.1
     */
    #[Test]
    public function theApplicationSpendsItsCodeWithTheSecretOfItsEnvironment(): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::user());

        // When / Then
        $this->signInClient('app', self::CALLBACK, self::SECRET);
    }

    /**
     * RP-Initiated Logout §3
     */
    #[Test]
    public function theApplicationComesBackToItsRouteAfterALogoutItAskedFor(): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::user());
        $idToken = $this->idTokenOfTheApplication();

        // When
        $this->browser->request('GET', '/logout', [
            'id_token_hint' => $idToken,
            'post_logout_redirect_uri' => self::PAGE,
        ]);

        // Then
        static::assertSame(Response::HTTP_FOUND, $this->browser->getResponse()->getStatusCode());
        static::assertSame(self::PAGE, $this->browser->getResponse()->headers->get('Location'));
    }

    /**
     * OIDC Core §2
     */
    #[Test]
    public function theApplicationSignsItsUsersInThroughItsOwnFirewall(): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::user());

        // When
        $this->browser->request('GET', 'https://op.test/application/oidc/start');
        $this->browser->followRedirect();
        $this->browser->followRedirect();
        $this->browser->request('GET', self::PAGE);

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode(), self::string($this->browser->getResponse()->getContent()));
        static::assertSame('alice-subject', $this->browser->getResponse()->getContent());
    }

    private function idTokenOfTheApplication(): string
    {
        $this->browser->request('GET', '/authorize', self::authorizationParameters('app', [
            'redirect_uri' => self::CALLBACK,
        ]));
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'authorization_code',
                'code' => self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The application got no code.'),
                'redirect_uri' => self::CALLBACK,
                'code_verifier' => self::CODE_VERIFIER,
            ],
            server: [
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('app:' . self::SECRET),
            ],
        );

        return self::string(self::json($this->browser->getResponse())['id_token'] ?? null);
    }
}
