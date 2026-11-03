<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function base64_encode;
use Beffroi\Core\Tests\Fixture\SoftwareAuthenticator;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * The acceptance of issue #266 (CIBA Core §7.1, decision 0010): a client with no browser anywhere asks
 * for a class, and what that costs is asked of the one person who can pay it, on the page where they
 * answer. A password session of a user who holds a passkey, asked for a class only a passkey proves, is
 * sent to the login of this provider for the missing factor and comes back to answer; the same request
 * from a user who holds no passkey is answered at once with what their session proves, the demand being a
 * request and not a condition (OIDC Core §5.5.1.1). Refusing is offered throughout (§11).
 */
final class BackchannelStepUpTest extends PasskeyTestCase
{
    private const string CLIENT_ID = 'terminal-app';

    private const string SECRET = 'terminal-secret-of-at-least-32-characters';

    private const string PASSWORD = 'correct horse battery staple';

    /**
     * §7.1, decision 0010: the client asked for "phr", the session proves a password, and a passkey of
     * this user would; the page does not record the approval, it asks for the proof.
     */
    #[Test]
    public function aRequestForAClassTheSessionDoesNotProveSendsTheUserToTheLogin(): void
    {
        // Given
        $this->enrol(self::userWithPassword('alice', self::PASSWORD), self::device());
        $this->ask([
            'acr_values' => 'phr',
        ]);

        // When
        $this->answer('Allow');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('/login', $response->headers->get('Location'));
    }

    /**
     * Decision 0010: the login page names the classes that would do and the kinds of credential of this
     * user that would reach one, and it names no client, serving no request of a browser.
     */
    #[Test]
    public function theLoginPageNamesWhatIsMissingAndNoClient(): void
    {
        // Given
        $this->enrol(self::userWithPassword('alice', self::PASSWORD), self::device());
        $this->ask([
            'acr_values' => 'phr',
        ]);
        $this->answer('Allow');

        // When
        $crawler = $this->browser->request('GET', '/login');

        // Then
        $requirement = $crawler->filter('p[data-requirement]');
        static::assertSame('stronger_factor_required', $requirement->attr('data-requirement'));
        static::assertSame('phr', $requirement->attr('data-acr'));
        static::assertCount(1, $crawler->filter('p[data-step-up="passkey"]'));
        static::assertCount(0, $crawler->filter('p[data-step-up="password"]'));
        static::assertStringNotContainsString(
            'Payment terminal at the counter',
            self::string($this->browser->getResponse()->getContent()),
        );
    }

    /**
     * Decision 0010: the passkey proven on the same session satisfies the request, the browser comes back
     * to the page it was sent from, and the approval goes through.
     */
    #[Test]
    public function theProofGivenBringsTheBrowserBackAndTheApprovalGoesThrough(): void
    {
        // Given
        $device = self::device();
        $this->enrol(self::userWithPassword('alice', self::PASSWORD), $device);
        $this->ask([
            'acr_values' => 'phr',
        ]);
        $this->answer('Allow');

        // When
        $this->loginWithPasskeyOnThePendingPage($device);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('/account/approvals', $response->headers->get('Location'));
        $this->answer('Allow');
        static::assertCount(1, $this->browser->getCrawler()->filter('p[data-answer="approved"]'));
    }

    /**
     * OIDC Core §2: the "acr" of the tokens is the requested class the session proved, once it proved it.
     */
    #[Test]
    public function theTokensOfSuchAnApprovalNameTheClassThatWasProven(): void
    {
        // Given
        self::signingKey();
        $device = self::device();
        $this->enrol(self::userWithPassword('alice', self::PASSWORD), $device);
        $authRequestId = self::string(
            self::json($this->ask([
                'acr_values' => 'phr',
            ]))['auth_req_id'],
        );
        $this->answer('Allow');
        $this->loginWithPasskeyOnThePendingPage($device);
        $this->answer('Allow');

        // When
        self::mockTime('+5 seconds');
        $this->come($authRequestId);

        // Then
        $tokens = self::json($this->browser->getResponse());
        $claims = self::claimsOf(self::string($tokens['id_token']));
        static::assertSame('phr', $claims['acr']);
    }

    /**
     * OIDC Core §5.5.1.1: a class no credential of this user could ever reach is asked of nobody; the
     * approval goes through at once and the tokens say what the session proved.
     */
    #[Test]
    public function aClassNoCredentialOfTheUserCouldReachIsAnsweredWithWhatTheSessionProves(): void
    {
        // Given
        self::signingKey();
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $authRequestId = self::string(
            self::json($this->ask([
                'acr_values' => 'phr',
            ]))['auth_req_id'],
        );
        $this->signIn($alice);
        $this->answer('Allow');

        // When
        self::mockTime('+5 seconds');
        $this->come($authRequestId);

        // Then
        $claims = self::claimsOf(self::string(self::json($this->browser->getResponse())['id_token']));
        static::assertSame('1', $claims['acr']);
    }

    /**
     * §11: refusing is an answer of full right and is never held behind a proof; a user who will not sign
     * in again ends the request rather than being kept on a page.
     */
    #[Test]
    public function aRefusalIsOfferedWhateverTheSessionProves(): void
    {
        // Given
        $this->enrol(self::userWithPassword('alice', self::PASSWORD), self::device());
        $authRequestId = self::string(
            self::json($this->ask([
                'acr_values' => 'phr',
            ]))['auth_req_id'],
        );

        // When
        $this->answer('Refuse');

        // Then
        self::mockTime('+5 seconds');
        $this->come($authRequestId);
        static::assertSame('access_denied', self::json($this->browser->getResponse())['error']);
    }

    /**
     * The passkey login of a page of the provider that is waiting for one: the same two calls the login
     * page makes, with no interaction to name.
     */
    private function loginWithPasskeyOnThePendingPage(SoftwareAuthenticator $device): void
    {
        $crawler = $this->browser->request('GET', '/login');
        $token = $crawler->filter('form[data-passkey="login"] input[name="_csrf_token"]')->attr('value');
        static::assertIsString($token);
        $this->browser->request('POST', '/login/passkey/options');
        $options = self::string($this->browser->getResponse()->getContent());
        $this->browser->request('POST', '/login/passkey', [
            '_csrf_token' => $token,
            '_passkey' => $device->get($options),
        ]);
    }

    /**
     * @param array<string, string> $parameters
     */
    private function ask(array $parameters = []): Response
    {
        $this->browser->request(
            'POST',
            '/backchannel_authentication',
            [
                'scope' => 'openid profile',
                'login_hint' => 'alice-subject',
                ...$parameters,
            ],
            server: self::credentials(),
        );

        return $this->browser->getResponse();
    }

    private function come(string $authRequestId): void
    {
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'urn:openid:params:grant-type:ciba',
                'auth_req_id' => $authRequestId,
            ],
            server: self::credentials(),
        );
    }

    private function answer(string $button): void
    {
        $crawler = $this->browser->request('GET', '/account/approvals');
        $this->browser->submit($crawler->selectButton($button)->form());
    }

    /**
     * @return array<string, string>
     */
    private static function credentials(): array
    {
        return [
            'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode(self::CLIENT_ID . ':' . self::SECRET),
        ];
    }
}
