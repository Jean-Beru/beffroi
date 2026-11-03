<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function base64_encode;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * Issue #282: the application is a client of the provider it serves, declared by the names of its
 * routes ("beffroi.self_client" in config_test.yml). The provider answers it as the first-party application it is, and
 * it signs its own users in through the "oidc_login" of Symfony, whose firewall names the three parameters the provider
 * exposes and nothing else of the provider.
 */
final class SelfClientFlowTest extends BrowserTestCase
{
    /**
     * The URL the router writes for the callback the route loader of Symfony declares for the firewall of the
     * application, under the origin of the issuer.
     */
    private const string CALLBACK = 'https://op.test/application/oidc/callback';

    /**
     * The URL of the page of the application, the route it comes back to after a logout.
     */
    private const string PAGE = 'https://op.test/application/me';

    /**
     * What the environment of this kernel gives the application (config_test.yml).
     */
    private const string SECRET = 'the-secret-of-the-host-application-of-this-kernel';

    /**
     * OIDC Core §3.1.2.4: consent is the rule, and a first-party application is the named exception its client
     * carries, so the application is answered with a code and nobody is shown a page.
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
     * RFC 6749 §2.3.1: the application authenticates at the token endpoint with the secret its environment gives it,
     * as any confidential client does.
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
     * RP-Initiated Logout §3: the application comes back to the route it named after a logout it asked for, the URL
     * the router writes for that route being the one it registered.
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
     * The whole of the issue: the application signs a person in at the provider it serves through the "oidc_login" of
     * Symfony, configured by nothing but the parameters the provider exposes, and knows them by the subject the provider
     * gave it (OIDC Core §2), every request its firewall sends the provider being answered by the provider itself.
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

    /**
     * The ID token the provider issues the application for the session the browser holds: an authorization request
     * nobody is asked to consent to, and its code spent with the secret of the application.
     */
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
