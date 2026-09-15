<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Controller;

use function base64_encode;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Port\AuthenticationSessionRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * OIDC RP-Initiated Logout 1.0 §2 to §4 and architecture §4.9, §5.2: the end session endpoint, its
 * confirmation page, and what the browser holds afterwards.
 */
final class EndSessionControllerTest extends BrowserTestCase
{
    /**
     * §4: a logout request from a browser that holds no session is honoured as is.
     */
    #[Test]
    public function aBrowserWithoutASessionIsLoggedOutAlready(): void
    {
        $this->browser->request('GET', '/logout');

        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        self::assertInteractionHeaders($response);
        static::assertStringContainsString('data-logged-out="yes"', self::string($response->getContent()));
    }

    /**
     * §2: without a hint the user is asked; the confirmation form carries the parameters over and ends
     * the session on yes, after which the browser holds nothing.
     */
    #[Test]
    public function withoutAHintTheUserConfirmsAndTheSessionEnds(): void
    {
        $session = $this->signIn(self::user('alice'));

        $crawler = $this->browser->request('GET', '/logout', [
            'client_id' => 'oidc-demo',
            'post_logout_redirect_uri' => 'https://demo.test/',
            'state' => 'after-logout',
        ]);

        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        self::assertInteractionHeaders($response);
        static::assertSame('no_hint', $crawler->filter('[data-reason]')->attr('data-reason'));
        static::assertSame('after-logout', $crawler->filter('input[name="state"]')->attr('value'));
        static::assertSame('oidc-demo', $crawler->filter('input[name="client_id"]')->attr('value'));

        $this->browser->submit($crawler->selectButton('Sign out')->form());

        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('https://demo.test/?state=after-logout', $response->headers->get('Location'));
        $ended = self::service('test.heidi.sessions', AuthenticationSessionRepositoryInterface::class)->find($session->id) ?? static::fail('The session is gone.');
        static::assertTrue($ended->hasEnded());

        // the browser is not bound to anything any more: an authorization request needs a login
        $this->browser->request('GET', '/authorize', self::authorizationParameters('oidc-demo'));
        static::assertStringStartsWith('/login?interaction=', self::string($this->browser->getResponse()->headers->get('Location')));
    }

    /**
     * §2: the user may refuse; nothing ends and the browser goes nowhere.
     */
    #[Test]
    public function theUserMayStaySignedIn(): void
    {
        $session = $this->signIn(self::user('alice'));
        $crawler = $this->browser->request('GET', '/logout', [
            'client_id' => 'oidc-demo',
            'post_logout_redirect_uri' => 'https://demo.test/',
        ]);

        $this->browser->submit($crawler->selectButton('Stay signed in')->form());

        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertFalse($response->headers->has('Location'));
        static::assertStringContainsString('data-logged-out="no"', self::string($response->getContent()));
        $kept = self::service('test.heidi.sessions', AuthenticationSessionRepositoryInterface::class)->find($session->id) ?? static::fail('The session is gone.');
        static::assertFalse($kept->hasEnded());
    }

    /**
     * §2: a hint that names the session the browser holds ends it without a question, the way
     * oidc_login sends it: id_token_hint and post_logout_redirect_uri, nothing else.
     */
    #[Test]
    public function aHintNamingTheSessionEndsItWithoutAQuestion(): void
    {
        $user = self::user('alice');
        $idToken = $this->idTokenOf($user);

        $this->browser->request('GET', '/logout', [
            'id_token_hint' => $idToken,
            'post_logout_redirect_uri' => 'https://demo.test/',
        ]);

        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('https://demo.test/', $response->headers->get('Location'));
        self::assertInteractionHeaders($response);
    }

    /**
     * §2: a hint of the same user but of another session asks first.
     */
    #[Test]
    public function aHintOfAnotherSessionAsksFirst(): void
    {
        $user = self::user('alice');
        $idToken = $this->idTokenOf($user);
        $this->signIn($user);

        $crawler = $this->browser->request('GET', '/logout', [
            'id_token_hint' => $idToken,
        ]);

        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame('different_session', $crawler->filter('[data-reason]')->attr('data-reason'));
    }

    /**
     * §4: a request found wrong is shown to the user, never redirected.
     */
    #[Test]
    public function anUnregisteredRedirectUriIsShownToTheUser(): void
    {
        $this->browser->request('GET', '/logout', [
            'client_id' => 'oidc-demo',
            'post_logout_redirect_uri' => 'https://attacker.example/',
        ]);

        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertFalse($response->headers->has('Location'));
        static::assertStringContainsString('data-error="invalid_request"', self::string($response->getContent()));
    }

    /**
     * The confirmation form is protected against cross-site submission: a forged "yes" ends nothing.
     */
    #[Test]
    public function aForgedConfirmationEndsNothing(): void
    {
        $session = $this->signIn(self::user('alice'));

        $this->browser->request('POST', '/logout', [
            'confirm' => 'yes',
            '_token' => 'forged',
        ]);

        static::assertSame(Response::HTTP_FORBIDDEN, $this->browser->getResponse()->getStatusCode());
        $kept = self::service('test.heidi.sessions', AuthenticationSessionRepositoryInterface::class)->find($session->id) ?? static::fail('The session is gone.');
        static::assertFalse($kept->hasEnded());
    }

    /**
     * An ID token issued to oidc-demo for a session of the user, obtained through the code flow, which
     * leaves the browser bound to that session.
     */
    private function idTokenOf(User $user): string
    {
        self::signingKey();
        $this->signIn($user);
        $this->browser->request('GET', '/authorize', self::authorizationParameters('oidc-demo'));
        $code = self::redirectedQuery($this->browser->getResponse())['code'];
        $this->browser->request('POST', '/token', [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => 'https://demo.test/login/check',
            'code_verifier' => self::CODE_VERIFIER,
        ], server: [
            'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('oidc-demo:demo-secret-of-at-least-32-characters-long'),
        ]);
        $tokens = self::json($this->browser->getResponse());
        static::assertIsString($tokens['id_token'] ?? null, self::string($this->browser->getResponse()->getContent()));

        return $tokens['id_token'];
    }
}
