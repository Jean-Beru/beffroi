<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Ciba;

use function base64_encode;
use Beffroi\Bundle\Ciba\Conformance\AutomatedApprovalController;
use Beffroi\Bundle\Tests\Functional\Controller\BrowserTestCase;
use function http_build_query;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use Symfony\Component\HttpFoundation\Response;

/**
 * What the OpenID conformance suite answers a backchannel request with when nobody is there to answer it
 * ("automated_ciba_approval_url", tests/conformance/README.md), imported by the test kernel under
 * /ciba/conformance as an application imports it in development. The FAPI-CIBA plan itself runs against
 * the stack; what it asks of this endpoint is played here.
 */
final class CibaConformanceTest extends BrowserTestCase
{
    private const string CLIENT_ID = 'terminal-app';

    private const string SECRET = 'terminal-secret-of-at-least-32-characters';

    private const string PASSWORD = 'correct horse battery staple';

    private const string OTHER_PASSWORD = 'a password of somebody else';

    /**
     * CIBA Core §10.1: the answer of the suite is the answer of the user, and the client that comes back
     * gets its tokens.
     */
    #[Test]
    public function theSuiteApprovesARequestAndTheClientGetsItsTokens(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $authRequestId = self::string(self::json($this->ask())['auth_req_id']);

        // When
        $answered = $this->answer($authRequestId, AutomatedApprovalController::ANSWER_ALLOW);

        // Then
        static::assertSame(Response::HTTP_OK, $answered->getStatusCode(), self::string($answered->getContent()));
        static::assertSame(AutomatedApprovalController::ANSWER_ALLOW, self::json($answered)['answer']);
        self::mockTime('+5 seconds');
        $this->come($authRequestId);
        static::assertIsString(self::json($this->browser->getResponse())['access_token']);
    }

    /**
     * §11: the suite refuses on behalf of the user, and the client learns it.
     */
    #[Test]
    public function theSuiteRefusesARequestAndTheClientLearnsIt(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $authRequestId = self::string(self::json($this->ask())['auth_req_id']);

        // When
        $answered = $this->answer($authRequestId, AutomatedApprovalController::ANSWER_DENY);

        // Then
        static::assertSame(Response::HTTP_OK, $answered->getStatusCode(), self::string($answered->getContent()));
        self::mockTime('+5 seconds');
        $this->come($authRequestId);
        static::assertSame('access_denied', self::json($this->browser->getResponse())['error']);
    }

    /**
     * Decision 0006: a session is opened on a proof here as everywhere, so a wrong password answers
     * nothing and the request goes on waiting.
     */
    #[Test]
    public function aWrongPasswordAnswersNothing(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $authRequestId = self::string(self::json($this->ask())['auth_req_id']);

        // When
        $answered = $this->answer($authRequestId, AutomatedApprovalController::ANSWER_ALLOW, password: 'not the password');

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $answered->getStatusCode());
        self::mockTime('+5 seconds');
        $this->come($authRequestId);
        static::assertSame('authorization_pending', self::json($this->browser->getResponse())['error']);
    }

    /**
     * §7.1: this endpoint reads the list of one user as the page does, so a request made for somebody
     * else is not answerable through it either.
     */
    #[Test]
    public function aRequestOfSomebodyElseIsNotAnswerable(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        self::userWithPassword('bob', self::OTHER_PASSWORD);
        $authRequestId = self::string(self::json($this->ask())['auth_req_id']);

        // When
        $answered = $this->answer($authRequestId, AutomatedApprovalController::ANSWER_ALLOW, username: 'bob', password: self::OTHER_PASSWORD);

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $answered->getStatusCode());
        self::mockTime('+5 seconds');
        $this->come($authRequestId);
        static::assertSame('authorization_pending', self::json($this->browser->getResponse())['error']);
    }

    /**
     * An identifier this provider never issued names no request, and says so as one already answered
     * does.
     */
    #[Test]
    public function anIdentifierOfNoRequestIsRefused(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);

        // When
        $answered = $this->answer('an-identifier-nobody-was-ever-handed', AutomatedApprovalController::ANSWER_ALLOW);

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $answered->getStatusCode());
    }

    /**
     * The two words the suite substitutes and nothing else: what it wants done is read, never guessed.
     */
    #[Test]
    public function anAnswerThatIsNeitherOfTheTwoIsRefused(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $authRequestId = self::string(self::json($this->ask())['auth_req_id']);

        // When
        $answered = $this->answer($authRequestId, 'maybe');

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $answered->getStatusCode());
        self::mockTime('+5 seconds');
        $this->come($authRequestId);
        static::assertSame('authorization_pending', self::json($this->browser->getResponse())['error']);
    }

    private function ask(): Response
    {
        self::signingKey();
        $this->browser->request(
            'POST',
            '/backchannel_authentication',
            [
                'scope' => 'openid profile',
                'login_hint' => 'alice-subject',
            ],
            server: self::credentials(),
        );

        return $this->browser->getResponse();
    }

    /**
     * The call the suite makes: everything in the query, no body at all.
     */
    private function answer(string $authRequestId, string $answer, string $username = 'alice', string $password = self::PASSWORD): Response
    {
        $this->browser->request('POST', sprintf('/ciba/conformance/approval?%s', http_build_query([
            AutomatedApprovalController::REQUEST_PARAMETER => $authRequestId,
            AutomatedApprovalController::ANSWER_PARAMETER => $answer,
            AutomatedApprovalController::USERNAME_PARAMETER => $username,
            AutomatedApprovalController::PASSWORD_PARAMETER => $password,
        ])));

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
