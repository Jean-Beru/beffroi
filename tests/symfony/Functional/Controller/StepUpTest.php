<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function base64_encode;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * Decision 0010, Architecture §4.3
 */
final class StepUpTest extends PasskeyTestCase
{
    private const string PASSWORD = 'correct horse battery staple';

    /**
     * Decision 0010
     *
     * @param array<string, string> $parameters
     */
    #[Test]
    #[DataProvider('provideRequestsForAPasskeyClass')]
    public function aPasswordSessionAskedForAPasskeyClassGetsTheLoginPageForTheMissingFactor(array $parameters): void
    {
        // Given
        $this->enrol(self::userWithPassword('alice', self::PASSWORD), self::device(), signedInAt: self::currentSecond()->modify('-10 minutes'));
        $interaction = $this->authorize($parameters);

        // When
        $crawler = $this->loginPage($interaction);

        // Then
        $requirement = $crawler->filter('p[data-requirement]');
        static::assertSame('stronger_factor_required', $requirement->attr('data-requirement'));
        static::assertSame('phr', $requirement->attr('data-acr'));
        static::assertCount(1, $crawler->filter('p[data-step-up="passkey"]'));
        static::assertCount(0, $crawler->filter('p[data-step-up="password"]'));
        static::assertCount(1, $crawler->filter('form input[name="_password"]'));
        static::assertCount(1, $crawler->filter('form[data-passkey="login"]'));
    }

    /**
     * @return iterable<string, array{array<string, string>}>
     */
    public static function provideRequestsForAPasskeyClass(): iterable
    {
        yield 'essential, the claims parameter' => [[
            'claims' => '{"id_token": {"acr": {"essential": true, "values": ["phr"]}}}',
        ]];
        yield 'voluntary, acr_values' => [[
            'acr_values' => 'phr',
        ]];
        yield 'with prompt=login, as the re-authentication of Symfony sends it' => [[
            'acr_values' => 'phr',
            'prompt' => 'login',
        ]];
    }

    /**
     * Architecture §4.3
     *
     * @param array<string, string> $parameters
     */
    #[Test]
    #[DataProvider('provideEssentialRequestsForAPasskeyClass')]
    public function aPasswordSessionWithoutAPasskeyAskedForAnEssentialPasskeyClassGoesBackToTheClientBeforeAnyPage(array $parameters): void
    {
        // Given
        $this->signIn(self::userWithPassword('alice', self::PASSWORD), self::currentSecond()->modify('-10 minutes'));

        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters('oidc-demo', $parameters));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        $query = self::redirectedQuery($response);
        static::assertSame('unmet_authentication_requirements', $query['error']);
        static::assertSame('state-of-the-client', $query['state']);
        static::assertSame('https://op.test', $query['iss']);
    }

    /**
     * @return iterable<string, array{array<string, string>}>
     */
    public static function provideEssentialRequestsForAPasskeyClass(): iterable
    {
        yield 'the claims parameter' => [[
            'claims' => '{"id_token": {"acr": {"essential": true, "values": ["phr"]}}}',
        ]];
        yield 'with prompt=login, before the page the prompt asks for' => [[
            'claims' => '{"id_token": {"acr": {"essential": true, "values": ["phr"]}}}',
            'prompt' => 'login',
        ]];
    }

    /**
     * Architecture §4.3
     */
    #[Test]
    public function aPasswordSessionWithoutAPasskeyAskedForAVoluntaryPasskeyClassGetsTheCodeAtOnceWithTheCurrentClass(): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::userWithPassword('alice', self::PASSWORD), self::currentSecond()->modify('-10 minutes'));
        $this->browser->request('GET', '/authorize', self::authorizationParameters('oidc-demo', [
            'acr_values' => 'phr',
        ]));
        $code = self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');

        // When
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => 'https://demo.test/login/check',
                'code_verifier' => self::CODE_VERIFIER,
            ],
            server: [
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('oidc-demo:demo-secret-of-at-least-32-characters-long'),
            ],
        );

        // Then
        $claims = self::claimsOf(self::string(self::json($this->browser->getResponse())['id_token']));
        static::assertSame('1', $claims['acr']);
        static::assertSame(['pwd'], $claims['amr']);
    }

    /**
     * Architecture §4.3
     */
    #[Test]
    public function aPasswordSessionWithoutAPasskeyAskedForAVoluntaryPasskeyClassWithPromptLoginGetsAPlainReauthentication(): void
    {
        // Given
        $this->signIn(self::userWithPassword('alice', self::PASSWORD), self::currentSecond()->modify('-10 minutes'));
        $interaction = $this->authorize([
            'acr_values' => 'phr',
            'prompt' => 'login',
        ]);

        // When
        $crawler = $this->loginPage($interaction);

        // Then
        static::assertSame('reauthentication_requested', $crawler->filter('p[data-requirement]')->attr('data-requirement'));
        static::assertCount(0, $crawler->filter('p[data-step-up]'));
        static::assertCount(1, $crawler->filter('form input[name="_password"]'));
        static::assertCount(1, $crawler->filter('form[data-passkey="login"]'));
    }

    /**
     * RFC 8176 §2
     */
    #[Test]
    public function thePasskeyProvenDuringTheStepUpSatisfiesTheRequestAndTheIdTokenSaysSo(): void
    {
        // Given
        self::signingKey();
        $device = self::device();
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $this->enrol($alice, $device, signedInAt: self::currentSecond()->modify('-10 minutes'));
        $first = $this->boundSession();
        $this->browser->request('GET', '/authorize', self::authorizationParameters('oidc-demo', [
            'claims' => '{"id_token": {"acr": {"essential": true, "values": ["phr"]}}}',
        ]));
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $this->loginWithPasskey($interaction, $device);
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);
        $code = self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');

        // When
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => 'https://demo.test/login/check',
                'code_verifier' => self::CODE_VERIFIER,
            ],
            server: [
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('oidc-demo:demo-secret-of-at-least-32-characters-long'),
            ],
        );

        // Then
        $claims = self::claimsOf(self::string(self::json($this->browser->getResponse())['id_token']));
        static::assertSame('phr', $claims['acr']);
        static::assertSame(['pwd', 'hwk', 'user', 'mfa'], $claims['amr']);
        static::assertGreaterThan($first->authenticatedAt()->getTimestamp(), $claims['auth_time']);
        static::assertSame($first->id->toRfc4122(), $claims['sid']);
        static::assertCount(1, self::sessionsOf('alice'));
        static::assertSame([], self::events(UserAuthenticated::class), 'No session was opened.');
    }

    /**
     * OIDC Core §5.5.1.1
     */
    #[Test]
    public function anEssentialClassStillUnsatisfiedAfterTheLoginGoesBackToTheClient(): void
    {
        // Given
        $this->enrol(self::userWithPassword('alice', self::PASSWORD), self::device(), signedInAt: self::currentSecond()->modify('-10 minutes'));
        $interaction = $this->authorize([
            'claims' => '{"id_token": {"acr": {"essential": true, "values": ["phr"]}}}',
        ]);
        self::aSecondLater();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // When
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        $query = self::redirectedQuery($response);
        static::assertSame('unmet_authentication_requirements', $query['error']);
        static::assertSame('state-of-the-client', $query['state']);
        static::assertSame('https://op.test', $query['iss']);
    }

    /**
     * OIDC Core §5.5.1.1
     */
    #[Test]
    public function aVoluntaryClassStillUnsatisfiedAfterTheLoginGetsTheCodeWithTheCurrentClass(): void
    {
        // Given
        self::signingKey();
        $this->enrol(self::userWithPassword('alice', self::PASSWORD), self::device(), signedInAt: self::currentSecond()->modify('-10 minutes'));
        $this->browser->request('GET', '/authorize', self::authorizationParameters('oidc-demo', [
            'acr_values' => 'phr',
        ]));
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        self::aSecondLater();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);
        $code = self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');

        // When
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => 'https://demo.test/login/check',
                'code_verifier' => self::CODE_VERIFIER,
            ],
            server: [
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('oidc-demo:demo-secret-of-at-least-32-characters-long'),
            ],
        );

        // Then
        $claims = self::claimsOf(self::string(self::json($this->browser->getResponse())['id_token']));
        static::assertSame('1', $claims['acr']);
        static::assertSame(['pwd'], $claims['amr']);
    }

    /**
     * OIDC Core §3.1.2.6
     */
    #[Test]
    public function promptNoneWithAStepUpIsLoginRequired(): void
    {
        // Given
        $this->enrol(self::user('alice'), self::device(), signedInAt: self::currentSecond()->modify('-10 minutes'));

        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters('native-app', [
            'acr_values' => 'phr',
            'prompt' => 'none',
        ]));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('login_required', self::redirectedQuery($response)['error']);
    }

    #[Test]
    public function aSessionSatisfyingTheClassAskedForGetsTheCodeAtOnce(): void
    {
        // Given
        $device = self::device();
        $this->enrol(self::user('alice'), $device);
        $this->forgetTheBrowser();
        $this->loginWithPasskey($this->authorize(), $device);

        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters('oidc-demo', [
            'acr_values' => 'phr',
        ]));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertArrayHasKey('code', self::redirectedQuery($response));
    }

    private function submitLogin(string $interaction, string $username, string $password): void
    {
        $form = $this->loginPage($interaction)->selectButton('Sign in')->form();
        $form['_username'] = $username;
        $form['_password'] = $password;
        $this->browser->submit($form);
    }
}
