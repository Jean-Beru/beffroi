<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Ciba;

use function base64_encode;
use App\Ciba\Conformance\AutomatedApprovalController;
use App\Tests\Symfony\Functional\Controller\BrowserTestCase;
use function http_build_query;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use Symfony\Component\HttpFoundation\Response;

final class CibaConformanceTest extends BrowserTestCase
{
    private const string CLIENT_ID = 'terminal-app';

    private const string SECRET = 'terminal-secret-of-at-least-32-characters';

    private const string PASSWORD = 'correct horse battery staple';

    private const string OTHER_PASSWORD = 'a password of somebody else';

    /**
     * CIBA Core §10.1
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
     * CIBA Core §11
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
     * Decision 0006
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
     * CIBA Core §7.1
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
